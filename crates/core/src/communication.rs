//! Native directed mail. Immutable author evidence, service disclosure and
//! mailbox delivery are separate proofs; none establishes model execution.
#[path="communication_host_report.rs"]
mod host_report;

use crate::{
    canonical::{canonical, Path},
    crypto::{base64url, decode_base64url, sha256, sha256_hex, verifying_key},
    prepared_command::{
        verify_structure_author_intent, VerifiedPreparedCommand, VerifiedStructureAuthorIntent,
    },
    receipt_wire::{
        verify_http_response_with_path, VerifiedCommandResponse, WireReceiptExpectation,
    },
    structure_content::{
        open_content_with_aad, seal_content_with_aad, StructureContentError, StructureSealedContent,
    },
    structure_execution::PROFILE,
    wire_json::{canonical_wire_value, parse_wire_json_bounded, WireValue},
};
use ed25519_dalek::{Signature, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use zeroize::Zeroizing;

pub const FEATURE: &str = "native-mailbox-v1";
pub const FRAME_TYPE: &str = "peerwork.mailbox-frame.v1+jws";
pub const STREAM_TYPE: &str = "peerwork.mailbox-stream.v1+jws";
/// Includes envelope/JWS escaping overhead beyond the service's one-MiB data budget.
pub const MAX_FRAME_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_FRAME_NODES: usize = 16_000;
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;

#[derive(Debug, Error)]
#[error("invalid or mismatched native communication evidence")]
pub struct CommunicationError;
type Result<T> = std::result::Result<T, CommunicationError>;
fn text(v: &WireValue, key: &str) -> Result<String> {
    v.get(key)
        .and_then(WireValue::as_string)
        .ok_or(CommunicationError)
}
fn number(v: &WireValue, key: &str) -> Result<u64> {
    let n = v
        .get(key)
        .and_then(WireValue::as_number)
        .ok_or(CommunicationError)?;
    if !n.is_finite() || n.fract() != 0.0 || n < 0.0 || n > MAX_SEQUENCE as f64 {
        return Err(CommunicationError);
    }
    Ok(n as u64)
}
fn flag(v: &WireValue, key: &str) -> Result<bool> {
    match v.get(key) {
        Some(WireValue::Bool(v)) => Ok(*v),
        _ => Err(CommunicationError),
    }
}
fn array<'a>(v: &'a WireValue, key: &str, max: usize) -> Result<&'a [WireValue]> {
    match v.get(key) {
        Some(WireValue::Array(v)) if v.len() <= max => Ok(v),
        _ => Err(CommunicationError),
    }
}
fn token(v: &str) -> bool {
    v.len() == 43
        && v.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
}
fn digest(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
}
fn exact(v: &WireValue, names: &[&str]) -> Result<()> {
    if v.object_len() != Some(names.len()) || names.iter().any(|name| v.get(name).is_none()) {
        return Err(CommunicationError);
    }
    Ok(())
}
fn token_field(v: &WireValue, name: &str) -> Result<String> {
    let s = text(v, name)?;
    if !token(&s) {
        return Err(CommunicationError);
    }
    Ok(s)
}
fn wire<T: serde::de::DeserializeOwned>(v: &WireValue) -> Result<T> {
    serde_json::from_str(
        &canonical_wire_value(v, Path::STRUCTURED).map_err(|_| CommunicationError)?,
    )
    .map_err(|_| CommunicationError)
}
fn id(value: serde_json::Value) -> Result<String> {
    Ok(base64url(&sha256(
        canonical(&value, Path::SecureArtifact)
            .map_err(|_| CommunicationError)?
            .as_bytes(),
    )))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MailboxAddress {
    pub mailbox_id: String,
    pub membership_id: String,
}
impl MailboxAddress {
    pub fn validate(&self) -> Result<()> {
        if token(&self.mailbox_id) && token(&self.membership_id) {
            Ok(())
        } else {
            Err(CommunicationError)
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageContentContext {
    pub workspace_id: String,
    pub actor_id: String,
    pub command_id: String,
    pub conversation_id: String,
    pub reply_to: Option<String>,
    pub reply_address: Option<MailboxAddress>,
    pub recipients: Vec<MailboxAddress>,
}
impl MessageContentContext {
    pub fn from_command(command: &WireValue) -> Result<Self> {
        if text(command, "action_id")? != "structure.message.send"
            || command.get("instance_id") != Some(&WireValue::Null)
            || command.get("protocol_digest") != Some(&WireValue::Null)
            || command.get("expected_workspace_revision") != Some(&WireValue::Null)
            || command.get("expected_instance_revision") != Some(&WireValue::Null)
            || !matches!(command.get("exact_input_refs"),Some(WireValue::Array(items)) if items.is_empty())
        {
            return Err(CommunicationError);
        }
        let body = command.get("body").ok_or(CommunicationError)?;
        let WireValue::Object(fields) = body else {
            return Err(CommunicationError);
        };
        if fields.iter().any(|(key, _)| {
            ![
                "profile",
                "conversation_id",
                "reply_to",
                "reply_address",
                "recipients",
                "content",
            ]
            .iter()
            .any(|name| key.iter().copied().eq(name.encode_utf16()))
        }) || text(body, "profile")? != PROFILE
        {
            return Err(CommunicationError);
        }
        let reply_to = match body.get("reply_to") {
            None | Some(WireValue::Null) => None,
            Some(WireValue::String(v)) => {
                Some(String::from_utf16(v).map_err(|_| CommunicationError)?)
            }
            _ => return Err(CommunicationError),
        };
        let reply_address = match body.get("reply_address") {
            None | Some(WireValue::Null) => None,
            Some(v) => Some(wire(v)?),
        };
        let result = Self {
            workspace_id: token_field(command, "workspace_id")?,
            actor_id: token_field(command, "actor_id")?,
            command_id: token_field(command, "command_id")?,
            conversation_id: token_field(body, "conversation_id")?,
            reply_to,
            reply_address,
            recipients: array(body, "recipients", 8)?
                .iter()
                .map(wire)
                .collect::<Result<_>>()?,
        };
        result.canonical_aad().map_err(|_| CommunicationError)?;
        Ok(result)
    }
    pub fn from_author(author: &VerifiedStructureAuthorIntent) -> Result<Self> {
        Self::from_command(author.command())
    }
    pub fn canonical_aad(&self) -> std::result::Result<String, StructureContentError> {
        if ![
            &self.workspace_id,
            &self.actor_id,
            &self.command_id,
            &self.conversation_id,
        ]
        .iter()
        .all(|s| token(s))
            || self.reply_to.as_ref().is_some_and(|v| !token(v))
            || self
                .reply_address
                .as_ref()
                .is_some_and(|v| v.validate().is_err())
            || self.recipients.is_empty()
            || self.recipients.len() > 8
            || self.recipients.iter().any(|v| v.validate().is_err())
        {
            return Err(StructureContentError::Invalid);
        }
        let mut seen = std::collections::BTreeSet::new();
        if self.recipients.iter().any(|v| !seen.insert(&v.mailbox_id)) {
            return Err(StructureContentError::Invalid);
        }
        canonical(&json!({"format":"peerwork.message-content.v1","profile":PROFILE,"workspace_id":self.workspace_id,
            "actor_id":self.actor_id,"command_id":self.command_id,"conversation_id":self.conversation_id,
            "reply_to":self.reply_to,"reply_address":self.reply_address,"recipients":self.recipients}),Path::SecureArtifact).map_err(|_|StructureContentError::Invalid)
    }
    pub fn message_id(&self) -> Result<String> {
        id(json!([
            "peerwork.message.v1",
            self.workspace_id,
            self.actor_id,
            self.command_id
        ]))
    }
}
pub fn seal_message_content(
    key: &[u8; 32],
    plaintext: &[u8],
    context: &MessageContentContext,
) -> std::result::Result<StructureSealedContent, StructureContentError> {
    seal_content_with_aad(key, plaintext, &context.canonical_aad()?)
}
pub fn open_message_content(
    key: &[u8; 32],
    sealed: &StructureSealedContent,
    context: &MessageContentContext,
) -> std::result::Result<Zeroizing<Vec<u8>>, StructureContentError> {
    open_content_with_aad(key, sealed, &context.canonical_aad()?)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", deny_unknown_fields)]
pub enum MessageContent {
    #[serde(rename = "WORKSPACE_E2EE")]
    WorkspaceE2ee { body: StructureSealedContent },
    #[serde(rename = "SOURCE")]
    Source {
        instance_id: String,
        protocol_digest: String,
        record_id: String,
        revision: u64,
    },
}
pub fn authored_message_content(
    author: &VerifiedStructureAuthorIntent,
) -> Result<(MessageContentContext, MessageContent)> {
    let context = MessageContentContext::from_author(author)?;
    let content: MessageContent = wire(
        author
            .command()
            .get("body")
            .and_then(|v| v.get("content"))
            .ok_or(CommunicationError)?,
    )?;
    match &content {
        MessageContent::WorkspaceE2ee { body } => {
            body.decoded_ciphertext().map_err(|_| CommunicationError)?;
            if body.algorithm != "A256GCM"
                || !token(&body.key_id)
                || body.nonce.len() != 16
                || decode_base64url(&body.nonce).is_err()
                || body.aad_digest
                    != sha256_hex(
                        context
                            .canonical_aad()
                            .map_err(|_| CommunicationError)?
                            .as_bytes(),
                    )
            {
                return Err(CommunicationError);
            }
        }
        MessageContent::Source {
            instance_id,
            protocol_digest,
            record_id,
            revision,
        } => {
            if !token(instance_id)
                || !token(record_id)
                || !digest(protocol_digest)
                || *revision == 0
                || *revision > MAX_SEQUENCE
            {
                return Err(CommunicationError);
            }
        }
    }
    Ok((context, content))
}

#[derive(Debug, Clone)]
pub struct VerifiedMessage {
    author: VerifiedStructureAuthorIntent,
    context: MessageContentContext,
    content: MessageContent,
    message_id: String,
    sender_membership: String,
    accepted_at: u64,
}
impl VerifiedMessage {
    pub fn author(&self) -> &VerifiedStructureAuthorIntent {
        &self.author
    }
    pub fn context(&self) -> &MessageContentContext {
        &self.context
    }
    pub fn content(&self) -> &MessageContent {
        &self.content
    }
    pub fn message_id(&self) -> &str {
        &self.message_id
    }
    /// Membership and acceptance time are attested by the verified service
    /// disclosure, not directly signed in the sender's original command.
    pub fn sender_membership(&self) -> &str {
        &self.sender_membership
    }
    pub fn accepted_at(&self) -> u64 {
        self.accepted_at
    }
}
fn message(
    value: &WireValue,
    audience: &[u16],
    workspace: &str,
    recipient: Option<&MailboxAddress>,
) -> Result<VerifiedMessage> {
    exact(
        value,
        &[
            "message_id",
            "sender_actor",
            "sender_membership",
            "accepted_at",
            "command_id",
            "intent_digest",
            "author_intent",
        ],
    )?;
    let jws = text(value, "author_intent")?;
    let author = verify_structure_author_intent(&jws, audience).map_err(|_| CommunicationError)?;
    let (context, content) = authored_message_content(&author)?;
    if context.workspace_id != workspace
        || context.actor_id != text(value, "sender_actor")?
        || context.command_id != text(value, "command_id")?
        || author.intent_digest() != text(value, "intent_digest")?
        || context.message_id()? != text(value, "message_id")?
        || recipient.is_some_and(|target| !context.recipients.contains(target))
    {
        return Err(CommunicationError);
    }
    Ok(VerifiedMessage {
        message_id: context.message_id()?,
        sender_membership: token_field(value, "sender_membership")?,
        accepted_at: number(value, "accepted_at")?,
        author,
        context,
        content,
    })
}

/// A source response authenticates the result/event independently of the SSE
/// envelope. It cannot be replaced with unsigned JSON that merely names an author.
fn source_proof(
    value: &WireValue,
    audience: &[u16],
    workspace: &str,
    key: &str,
) -> Result<(
    VerifiedStructureAuthorIntent,
    VerifiedCommandResponse,
    WireValue,
)> {
    let jws = text(value, "author_intent")?;
    let author = verify_structure_author_intent(&jws, audience).map_err(|_| CommunicationError)?;
    if author.workspace_id() != Some(workspace)
        || author.intent_digest() != text(value, "intent_digest")?
    {
        return Err(CommunicationError);
    }
    let response = value.get("source_response").ok_or(CommunicationError)?;
    let result = response.get("result").ok_or(CommunicationError)?;
    if text(result, "profile")? != PROFILE
        || text(result, "assurance")? != "BACKEND_CURRENT_STATE"
        || result
            .get("author_intent")
            .and_then(WireValue::as_string)
            .as_deref()
            != Some(jws.as_str())
        || matches!(
            result
                .get("status")
                .and_then(WireValue::as_string)
                .as_deref(),
            Some("REJECTED_NO_EFFECT" | "COMMITTED_RESULT_UNAVAILABLE")
        )
    {
        return Err(CommunicationError);
    }
    let response_wire =
        canonical_wire_value(response, Path::STRUCTURED).map_err(|_| CommunicationError)?;
    let expected = WireReceiptExpectation {
        audience_utf16: audience,
        receipt_key_id: key,
        actor_id: author.actor_id(),
        command_id: author.command_id(),
        intent_digest: author.intent_digest(),
        workspace_id: Some(workspace),
        protocol_digest: author.protocol_digest(),
    };
    let proof =
        verify_http_response_with_path(response_wire.as_bytes(), &expected, Path::STRUCTURED)
            .map_err(|_| CommunicationError)?;
    if text(result, "workspace_id")? != workspace {
        return Err(CommunicationError);
    }
    Ok((author, proof, result.clone()))
}

#[derive(Debug, Clone)]
pub struct MailboxPins {
    pub workspace_id: String,
    pub mailbox_id: String,
    pub membership_id: String,
    pub receiver_id: String,
    pub epoch: u64,
    pub destination_digest: String,
    pub binding_version: u64,
    pub after_sequence: u64,
    pub after_control_sequence: Option<u64>,
}
impl MailboxPins {
    pub fn validate(&self) -> Result<()> {
        if ![
            &self.workspace_id,
            &self.mailbox_id,
            &self.membership_id,
            &self.receiver_id,
        ]
        .iter()
        .all(|s| token(s))
            || !digest(&self.destination_digest)
            || self.epoch == 0
            || self.epoch > MAX_SEQUENCE
            || self.binding_version == 0
            || self.binding_version > MAX_SEQUENCE
            || self.after_sequence > MAX_SEQUENCE
            || self
                .after_control_sequence
                .is_some_and(|v| v > MAX_SEQUENCE)
        {
            return Err(CommunicationError);
        }
        Ok(())
    }
}
#[derive(Debug, Clone)]
pub struct VerifiedDelivery {
    envelope: WireValue,
    message: Option<VerifiedMessage>,
}
impl VerifiedDelivery {
    pub fn envelope(&self) -> &WireValue {
        &self.envelope
    }
    pub fn message(&self) -> Option<&VerifiedMessage> {
        self.message.as_ref()
    }
    pub fn sequence(&self) -> u64 {
        number(&self.envelope, "sequence").expect("verified")
    }
    pub fn delivery_id(&self) -> String {
        text(&self.envelope, "delivery_id").expect("verified")
    }
}
#[derive(Debug, Clone)]
pub struct VerifiedMailboxPage {
    mailbox: MailboxPins,
    actor_id: String,
    audience: Vec<u16>,
    service_key: String,
    frame_wire: Option<String>,
    items: Vec<VerifiedDelivery>,
    controls: Vec<WireValue>,
    mailbox_frontier: u64,
    checkpoint: u64,
    control_checkpoint: u64,
    more: bool,
    controls_more: bool,
}
impl VerifiedMailboxPage {
    pub fn mailbox(&self) -> &MailboxPins {
        &self.mailbox
    }
    pub fn actor_id(&self) -> &str {
        &self.actor_id
    }
    pub fn audience(&self) -> &[u16] {
        &self.audience
    }
    pub fn service_key(&self) -> &str {
        &self.service_key
    }
    pub fn frame_wire(&self) -> Option<&str> {
        self.frame_wire.as_deref()
    }
    pub fn items(&self) -> &[VerifiedDelivery] {
        &self.items
    }
    pub fn controls(&self) -> &[WireValue] {
        &self.controls
    }
    pub fn mailbox_frontier(&self) -> u64 {
        self.mailbox_frontier
    }
    pub fn checkpoint(&self) -> u64 {
        self.checkpoint
    }
    pub fn control_checkpoint(&self) -> u64 {
        self.control_checkpoint
    }
    pub fn more(&self) -> bool {
        self.more
    }
    pub fn controls_more(&self) -> bool {
        self.controls_more
    }
}
fn delivery(
    value: &WireValue,
    audience: &[u16],
    actor: &str,
    pins: &MailboxPins,
    key: &str,
) -> Result<VerifiedDelivery> {
    token_field(value, "delivery_id")?;
    number(value, "sequence")?;
    number(value, "created_at")?;
    let kind = text(value, "kind")?;
    let terminal = value.get("terminal_reason").is_some();
    let fields = if kind == "BUSINESS" {
        7
    } else if kind == "MESSAGE" {
        5
    } else {
        return Err(CommunicationError);
    };
    if value.object_len() != Some(fields) {
        return Err(CommunicationError);
    }
    if terminal {
        let reason = text(value, "terminal_reason")?;
        if !(kind == "MESSAGE"
            && ["MESSAGE_WITHDRAWN", "MESSAGE_SOURCE_UNAVAILABLE"].contains(&reason.as_str())
            || kind == "BUSINESS"
                && ["SUBSCRIPTION_STOPPED", "SOURCE_WITHDRAWN"].contains(&reason.as_str()))
        {
            return Err(CommunicationError);
        }
    }
    let mut verified = None;
    if kind == "MESSAGE" && !terminal {
        let msg = message(
            value.get("message").ok_or(CommunicationError)?,
            audience,
            &pins.workspace_id,
            Some(&MailboxAddress {
                mailbox_id: pins.mailbox_id.clone(),
                membership_id: pins.membership_id.clone(),
            }),
        )?;
        let expected = id(json!([
            "peerwork.delivery.v1",
            pins.workspace_id,
            pins.mailbox_id,
            msg.message_id(),
            null
        ]))?;
        if expected != text(value, "delivery_id")?
            || msg.accepted_at() != number(value, "created_at")?
        {
            return Err(CommunicationError);
        }
        verified = Some(msg);
    }
    if kind == "BUSINESS" {
        let sub = token_field(value, "subscription_id")?;
        if number(value, "subscription_revision")? == 0 {
            return Err(CommunicationError);
        }
        if !terminal {
            let business = value.get("business").ok_or(CommunicationError)?;
            exact(
                business,
                &[
                    "sequence",
                    "instance_id",
                    "kind",
                    "actor_id",
                    "summary",
                    "intent_digest",
                    "author_intent",
                    "source_response",
                ],
            )?;
            let (author, proof, result) =
                source_proof(business, audience, &pins.workspace_id, key)?;
            if author.action_id() != "structure.action"
                || text(business, "kind")? != "action.accepted"
                || text(business, "actor_id")? != author.actor_id()
                || business.get("instance_id") != author.command().get("instance_id")
                || proof.event_sequence() != Some(number(business, "sequence")?)
            {
                return Err(CommunicationError);
            }
            let summary = business.get("summary").ok_or(CommunicationError)?;
            if text(summary, "action_id")? != author.action_id() {
                return Err(CommunicationError);
            }
            let WireValue::Object(summary_fields) = summary else {
                return Err(CommunicationError);
            };
            for (field, actual) in summary_fields {
                let name = String::from_utf16(field).map_err(|_| CommunicationError)?;
                if name != "action_id" && result.get(&name) != Some(actual) {
                    return Err(CommunicationError);
                }
            }
            let expected = id(json!([
                "peerwork.delivery.v1",
                pins.workspace_id,
                pins.mailbox_id,
                number(business, "sequence")?,
                sub
            ]))?;
            if expected != text(value, "delivery_id")? {
                return Err(CommunicationError);
            }
        }
    }
    // `actor` is supplied from the verified read/stream scope, never from an item.
    if !token(actor) {
        return Err(CommunicationError);
    }
    Ok(VerifiedDelivery {
        envelope: value.clone(),
        message: verified,
    })
}
fn control(value: &WireValue, audience: &[u16], pins: &MailboxPins, key: &str) -> Result<()> {
    exact(
        value,
        &[
            "sequence",
            "kind",
            "target",
            "intent_digest",
            "author_intent",
            "source_response",
        ],
    )?;
    let (author, proof, result) = source_proof(value, audience, &pins.workspace_id, key)?;
    if proof.event_sequence() != Some(number(value, "sequence")?) {
        return Err(CommunicationError);
    }
    let target = value.get("target").ok_or(CommunicationError)?;
    let command = author.command();
    let body = command.get("body").ok_or(CommunicationError)?;
    match text(value, "kind")?.as_str() {
        "record.withdrawn" => {
            exact(
                target,
                &["instance_id", "protocol_digest", "record_id", "revision"],
            )?;
            if author.action_id() != "structure.record.withdraw"
                || target.get("instance_id") != command.get("instance_id")
                || target.get("protocol_digest") != command.get("protocol_digest")
                || target.get("record_id") != body.get("record_id")
                || target.get("revision") != body.get("revision")
            {
                return Err(CommunicationError);
            }
        }
        "communication.message.withdrawn" => {
            exact(target, &["message_id", "delivery_id"])?;
            if author.action_id() != "structure.message.withdraw"
                || target.get("message_id") != body.get("message_id")
                || text(target, "delivery_id")?
                    != id(json!([
                        "peerwork.delivery.v1",
                        pins.workspace_id,
                        pins.mailbox_id,
                        token_field(target, "message_id")?,
                        null
                    ]))?
            {
                return Err(CommunicationError);
            }
        }
        "communication.subscription.changed" => {
            exact(target, &["subscription_id", "stopped_revision"])?;
            if author.action_id() != "structure.communication.subscription.set"
                || text(body, "state")? != "STOPPED"
                || text(body, "mailbox_id")? != pins.mailbox_id
                || target.get("subscription_id") != body.get("subscription_id")
                || number(body, "expected_revision")?.checked_add(1)
                    != Some(number(target, "stopped_revision")?)
                || result
                    .get("subscription")
                    .and_then(|v| v.get("stopped_revision"))
                    != target.get("stopped_revision")
            {
                return Err(CommunicationError);
            }
        }
        _ => return Err(CommunicationError),
    }
    Ok(())
}
fn page(
    value: &WireValue,
    audience: &[u16],
    actor: &str,
    pins: &MailboxPins,
    key: &str,
) -> Result<VerifiedMailboxPage> {
    pins.validate()?;
    let items = array(value, "items", 32)?;
    let controls = array(value, "controls", 32)?;
    let mailbox_frontier = number(value, "mailbox_frontier")?;
    let checkpoint = number(value, "checkpoint")?;
    if checkpoint > mailbox_frontier {
        return Err(CommunicationError);
    }
    let control_checkpoint = number(value, "control_checkpoint")?;
    let more = flag(value, "more")?;
    let controls_more = flag(value, "controls_more")?;
    let mut sequence = pins.after_sequence;
    let mut ids = std::collections::BTreeSet::new();
    let mut verified = Vec::with_capacity(items.len());
    for item in items {
        let next = number(item, "sequence")?;
        if next <= sequence || !ids.insert(token_field(item, "delivery_id")?) {
            return Err(CommunicationError);
        }
        sequence = next;
        verified.push(delivery(item, audience, actor, pins, key)?);
    }
    if checkpoint < sequence
        || more && checkpoint != sequence
        || !more && checkpoint != mailbox_frontier
        || more
            && items.is_empty()
            && controls.is_empty()
            && pins.after_control_sequence == Some(control_checkpoint)
    {
        return Err(CommunicationError);
    }
    let mut control_sequence = pins.after_control_sequence.unwrap_or(0);
    for item in controls {
        let next = number(item, "sequence")?;
        if next <= control_sequence {
            return Err(CommunicationError);
        }
        control_sequence = next;
        control(item, audience, pins, key)?;
    }
    if control_checkpoint < control_sequence {
        return Err(CommunicationError);
    }
    Ok(VerifiedMailboxPage {
        mailbox: pins.clone(),
        actor_id: actor.into(),
        audience: audience.to_vec(),
        service_key: key.into(),
        frame_wire: None,
        items: verified,
        controls: controls.to_vec(),
        mailbox_frontier,
        checkpoint,
        control_checkpoint,
        more,
        controls_more,
    })
}

/// Verify the native mailbox sources after the outer command receipt has been
/// authenticated. Called by receipt_wire; not an alternative trust entry point.
pub(crate) fn verify_read(
    result: &WireValue,
    command: &WireValue,
    prepared: &VerifiedPreparedCommand,
    key: &str,
) -> Result<()> {
    let body = command.get("body").ok_or(CommunicationError)?;
    match prepared.action_id() {
        "structure.mailbox.report"=>{
            let report=result.get("report").ok_or(CommunicationError)?;
            host_report::verify(report,prepared.audience_utf16(),prepared.workspace_id().ok_or(CommunicationError)?,prepared.actor_id())?;
            let requested=body.get("report").ok_or(CommunicationError)?;
            if report.get("call_id")!=requested.get("call_id")||report.get("scope")!=requested.get("scope")||number(report,"report_sequence")?<number(requested,"report_sequence")? {return Err(CommunicationError);}
            Ok(())
        },
        "structure.message.receipts.read"=>{
            if result.get("message_id")!=body.get("message_id"){return Err(CommunicationError);}
            let mut mailboxes=std::collections::BTreeSet::new();
            for delivery in array(result,"deliveries",8)?{
                let mailbox=token_field(delivery,"mailbox_id")?;
                let expected=id(serde_json::json!(["peerwork.delivery.v1",prepared.workspace_id().ok_or(CommunicationError)?,mailbox,text(body,"message_id")?,null]))?;
                if token_field(delivery,"delivery_id")?!=expected||number(delivery,"sequence")?==0||!mailboxes.insert(mailbox){return Err(CommunicationError);}
                if let Some(value)=delivery.get("host_report").filter(|v|!matches!(v,WireValue::Null)){
                    host_report::verify(value,prepared.audience_utf16(),prepared.workspace_id().ok_or(CommunicationError)?,&text(delivery,"recipient_actor")?)?;
                    let scope=value.get("scope").ok_or(CommunicationError)?;
                    if scope.get("mailbox_id")!=delivery.get("mailbox_id")||scope.get("membership_id")!=delivery.get("membership_id")||scope.get("sequence")!=delivery.get("sequence")||scope.get("delivery_id")!=delivery.get("delivery_id"){return Err(CommunicationError);}
                }
            }
            Ok(())
        },
        "structure.communication.stream.get" => {
            if prepared.workspace_id().is_some() {
                return Err(CommunicationError);
            }
            let stream = result.get("stream").ok_or(CommunicationError)?;
            exact(
                stream,
                &["path", "token", "stream_id", "scopes", "expires_at"],
            )?;
            if text(stream, "path")? != "/api/workspace/v1/structure/communication/stream" {
                return Err(CommunicationError);
            }
            let claims = verify_typed(&text(stream, "token")?, STREAM_TYPE, key)?;
            exact(
                &claims,
                &[
                    "kind",
                    "audience",
                    "actor_id",
                    "authority",
                    "stream_id",
                    "scopes",
                    "expires_at",
                ],
            )?;
            if text(&claims, "kind")? != "peerwork.mailbox-stream.v1"
                || claims.get("audience").and_then(WireValue::as_utf16)
                    != Some(prepared.audience_utf16())
                || text(&claims, "actor_id")? != prepared.actor_id()
                || claims.get("authority") != command.get("authority")
                || claims.get("stream_id") != stream.get("stream_id")
                || claims.get("expires_at") != stream.get("expires_at")
                || claims.get("scopes") != stream.get("scopes")
            {
                return Err(CommunicationError);
            }
            token_field(stream, "stream_id")?;
            number(stream, "expires_at")?;
            let selected = array(stream, "scopes", 8)?;
            let requested = array(body, "scopes", 8)?;
            if selected.is_empty() || selected.len() != requested.len() {
                return Err(CommunicationError);
            }
            for (scope, request) in selected.iter().zip(requested) {
                exact(
                    scope,
                    &[
                        "workspace_id",
                        "mailbox_id",
                        "receiver_id",
                        "epoch",
                        "after_sequence",
                        "after_control_sequence",
                    ],
                )?;
                for name in [
                    "workspace_id",
                    "mailbox_id",
                    "receiver_id",
                    "epoch",
                    "after_sequence",
                ] {
                    if scope.get(name) != request.get(name) {
                        return Err(CommunicationError);
                    }
                }
                if request.get("after_control_sequence").is_some_and(|v| {
                    !matches!(v, WireValue::Null) && scope.get("after_control_sequence") != Some(v)
                }) {
                    return Err(CommunicationError);
                }
                number(scope, "after_control_sequence")?;
            }
            Ok(())
        }
        "structure.message.get" => {
            let msg = message(
                result.get("message").ok_or(CommunicationError)?,
                prepared.audience_utf16(),
                prepared.workspace_id().ok_or(CommunicationError)?,
                None,
            )?;
            if msg.message_id() != text(body, "message_id")? {
                return Err(CommunicationError);
            }
            Ok(())
        }
        "structure.mailbox.inbox.read" => {
            let mailbox = result.get("mailbox").ok_or(CommunicationError)?;
            if text(mailbox, "mailbox_id")? != text(body, "mailbox_id")?
                || text(mailbox, "actor_id")? != prepared.actor_id()
                || number(mailbox, "epoch")? != number(body, "epoch")?
            {
                return Err(CommunicationError);
            }
            let pins = MailboxPins {
                workspace_id: prepared.workspace_id().ok_or(CommunicationError)?.into(),
                mailbox_id: text(body, "mailbox_id")?,
                membership_id: text(mailbox, "membership_id")?,
                receiver_id: text(body, "receiver_id")?,
                epoch: number(body, "epoch")?,
                destination_digest: text(mailbox, "destination_digest")?,
                binding_version: number(mailbox, "binding_version")?,
                after_sequence: if body.get("after_sequence").is_some() {
                    number(body, "after_sequence")?
                } else {
                    0
                },
                after_control_sequence: match body.get("after_control_sequence") {
                    None | Some(WireValue::Null) => None,
                    _ => Some(number(body, "after_control_sequence")?),
                },
            };
            let verified = page(
                result,
                prepared.audience_utf16(),
                prepared.actor_id(),
                &pins,
                key,
            )?;
            let limit = if body.get("limit").is_some() {
                number(body, "limit")?
            } else {
                16
            };
            if verified.items().len() as u64 > limit {
                return Err(CommunicationError);
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

/// Caller pins are derived from a verified stream grant and mailbox claim. The
/// stream deadline is checked with the engine's monotonic authorization clock.
pub struct FramePins<'a> {
    pub audience: &'a [u16],
    pub actor_id: &'a str,
    pub stream_id: &'a str,
    pub mailbox: &'a MailboxPins,
    pub service_key: &'a str,
    pub server_time_floor: u64,
    pub expires_at: u64,
}
pub fn verify_mailbox_frame(wire: &[u8], expected: &FramePins<'_>) -> Result<VerifiedMailboxPage> {
    let envelope =
        parse_wire_json_bounded(wire, 40, MAX_FRAME_BYTES).map_err(|_| CommunicationError)?;
    bounded_nodes(&envelope)?;
    exact(&envelope, &["proof", "items", "controls"])?;
    let proof = verify_typed(&text(&envelope, "proof")?, FRAME_TYPE, expected.service_key)?;
    exact(
        &proof,
        &[
            "kind",
            "audience",
            "stream_id",
            "actor_id",
            "workspace_id",
            "mailbox_id",
            "receiver_id",
            "epoch",
            "destination_digest",
            "binding_version",
            "server_time",
            "mailbox_frontier",
            "checkpoint",
            "more",
            "items_digest",
            "control_checkpoint",
            "controls_more",
            "controls_digest",
        ],
    )?;
    let pins = expected.mailbox;
    pins.validate()?;
    if text(&proof, "kind")? != "peerwork.mailbox-frame.v1"
        || proof.get("audience").and_then(WireValue::as_utf16) != Some(expected.audience)
        || text(&proof, "stream_id")? != expected.stream_id
        || text(&proof, "actor_id")? != expected.actor_id
        || text(&proof, "workspace_id")? != pins.workspace_id
        || text(&proof, "mailbox_id")? != pins.mailbox_id
        || text(&proof, "receiver_id")? != pins.receiver_id
        || number(&proof, "epoch")? != pins.epoch
        || text(&proof, "destination_digest")? != pins.destination_digest
        || number(&proof, "binding_version")? != pins.binding_version
        || number(&proof, "server_time")? < expected.server_time_floor
        || number(&proof, "server_time")? >= expected.expires_at
    {
        return Err(CommunicationError);
    }
    for (name, hash) in [("items", "items_digest"), ("controls", "controls_digest")] {
        let value = envelope.get(name).ok_or(CommunicationError)?;
        if sha256_hex(
            canonical_wire_value(value, Path::STRUCTURED)
                .map_err(|_| CommunicationError)?
                .as_bytes(),
        ) != text(&proof, hash)?
        {
            return Err(CommunicationError);
        }
    }
    let mut combined = proof.clone();
    let WireValue::Object(fields) = &mut combined else {
        return Err(CommunicationError);
    };
    for name in ["items", "controls"] {
        fields.push((
            name.encode_utf16().collect(),
            envelope.get(name).ok_or(CommunicationError)?.clone(),
        ));
    }
    let mut verified = page(
        &combined,
        expected.audience,
        expected.actor_id,
        pins,
        expected.service_key,
    )?;
    verified.frame_wire =
        Some(canonical_wire_value(&envelope, Path::STRUCTURED).map_err(|_| CommunicationError)?);
    Ok(verified)
}
fn bounded_nodes(value: &WireValue) -> Result<()> {
    fn visit(v: &WireValue, left: &mut usize) -> Result<()> {
        if *left == 0 {
            return Err(CommunicationError);
        }
        *left -= 1;
        match v {
            WireValue::Array(items) => {
                for v in items {
                    visit(v, left)?;
                }
            }
            WireValue::Object(items) => {
                for (_, v) in items {
                    visit(v, left)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut left = MAX_FRAME_NODES;
    visit(value, &mut left)
}
fn verify_typed(jws: &str, typ: &str, key: &str) -> Result<WireValue> {
    if jws.len() > 8192 {
        return Err(CommunicationError);
    }
    let parts: Vec<_> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err(CommunicationError);
    }
    let header = parse_wire_json_bounded(
        &decode_base64url(parts[0]).map_err(|_| CommunicationError)?,
        3,
        256,
    )
    .map_err(|_| CommunicationError)?;
    exact(&header, &["alg", "typ", "kid"])?;
    if text(&header, "alg")? != "EdDSA"
        || text(&header, "typ")? != typ
        || text(&header, "kid")? != key
    {
        return Err(CommunicationError);
    }
    let sig: [u8; 64] = decode_base64url(parts[2])
        .map_err(|_| CommunicationError)?
        .try_into()
        .map_err(|_| CommunicationError)?;
    verifying_key(key)
        .map_err(|_| CommunicationError)?
        .verify(
            format!("{}.{}", parts[0], parts[1]).as_bytes(),
            &Signature::from_bytes(&sig),
        )
        .map_err(|_| CommunicationError)?;
    parse_wire_json_bounded(
        &decode_base64url(parts[1]).map_err(|_| CommunicationError)?,
        12,
        6000,
    )
    .map_err(|_| CommunicationError)
}
