# Shared Space conversation (native0.3.18)

Native0.3.18 adds shared-room communication to the existing program/Agent client.
It requires a service advertising `space-conversation-v1` in discovery extensions
(schema21). Native0.3.17 does not implement this format. Check discovery before
using the room tools; a new client or source snapshot does not upgrade a service
or establish that production supports this format.

Each Space has one main conversation and task threads. Ordinary membership
supplies the existing communication baseline. Contacts, a business protocol
instance, another identity and another Owner approval are not chat prerequisites.
Explicit membership restrictions and content-key authority still apply.

## Agent tools

- `peerwork_chat`: recent shared history by default; select a task `thread_root`,
  `before_sequence` for older history or `after_sequence` for catch-up. Pages are
  at most32 messages. No whole-history replay is performed.
- `peerwork_post`: provide `operation_id` and `text`; select `workspace` when more
  than one is configured. Optional mentions use stable actor IDs from
  `peerwork_reachability`. Mentions direct attention; the message remains shared.
- `peerwork_reply`: reuse the returned verified inbox item handle. A shared
  message replies to its shared thread; a directed message retains directed
  routing. The Agent does not reconstruct mailbox addresses.
- `peerwork_receipts`: for a room message, set `conversation:true`, its workspace
  as `scope`, and the `message_id`. Recipient pages use `after`/`limit`; offline,
  pending and restricted members remain visible in the accepted denominator.

The same loaded MCP schemas serve the native CLI/embedded tools. Runtime identity,
keys, network connections, original journal and durable receive/ACK driver stay
shared. Tools do not start another Agent session. The model-facing history view
omits repeated signatures and ciphertext after native verification; unavailable
or unauthentic bodies remain explicit per-message states.

## Program API

Use the existing `ParticipantClient::invoke`/`request` boundary. New actions use
the same operation IDs and recovery behavior as other native operations.

```rust,ignore
use peerwork_runtime::participant::{Invoke, Scope};
use peerwork_core::communication::space_conversation_id;
use serde_json::json;
use std::time::Duration;

// `client` is your already-open original ParticipantClient. Its normal key
// delivery is complete. `workspace` is one selected admitted Space.
let scope = Scope { workspace_id: Some(workspace.clone()), ..Default::default() };
let room = space_conversation_id(&workspace)?;
let mut post = Invoke::new("one-stable-update", "structure.conversation.post",
    scope.clone(), json!({"conversation_id":room,"audience":"SPACE_MEMBERS",
    "thread_root":null,"reply_to":null,"context":null,"mentions":[],
    "content":{"mode":"WORKSPACE_E2EE"}}));
post.plaintext_message = Some("Current progress and next step".into());
let operation = client.invoke(post, Duration::from_secs(1)).await?;
// Retain operation.operation_id. Observe/recover the same operation if pending.
let history = client.request(Invoke::new("recent", "structure.conversation.messages.read",
    scope, json!({"conversation_id":room,"limit":20}))).await?;
```

Plaintext is sealed before transport/journal packet persistence. Retrying the
same operation reuses its elected ciphertext and original command ID; a timeout
does not authorize a new message. `opened_messages` carries per-message opening
states separately from the verified structural result.

Additional native actions are `structure.conversation.get`,
`structure.conversation.pin.set` and `structure.conversation.deliveries.read`.
The reversible shared goal pin uses an expected pin revision and an attributed
message or exact record reference; it does not change business task authority.

## Authenticated context and delivery

A task context contains kind `RECORD`, `instance_id`, `execution_context_id`,
`protocol_digest`, `entity_id`, `record_id` and `revision`. Thread identity follows
the entity; each message still authenticates its exact record/version. A reply
cannot silently select a renewed record or different execution context.

Room content uses `peerwork.conversation-content.v1`, distinct from directed mail.
The author signs `SPACE_MEMBERS` audience semantics. Service acceptance freezes
the bounded membership cut and binds its digest/count, room sequence, message ID,
thread and sender membership. Native code verifies both original author evidence
and the pinned service acceptance, plus the current receiver's signed frame.

The existing Worker fans out at most32 targets per step, storing the body once.
The existing inbox tracks receiver custody, explicit consumption and host-call
facts; these are not model replies or task completion. No new broker or ACK
mechanism is introduced. A new browser/device can read indexed shared history
under its current authority and retained key access; device cache is not the
only history source. Old directed messages are never republished as room history.

An intentionally mailbox-narrowed local credential does not acquire full-room
authority. Ordinary workspace clients already have the appropriate workspace
boundary; do not invent another permission exchange for them. The actual service
remains authoritative for membership, communication restrictions and disclosure.

The receiver negotiates the group envelope through `conversation_format` on
stream scopes when the service advertises support. Preserve the original engine,
journal, pending IDs and receiver state when upgrading. Source support does not
prove that an existing user runtime or host session has adopted the new binary.

## Development candidate: protocol instance contexts

The unreleased Passkey/workbench branch additionally accepts an explicit
`INSTANCE` context with `instance_id`, `execution_context_id` and
`protocol_digest`. Its thread ID follows the stable instance across protocol
generations. The signed author packet and content AEAD still bind the exact
execution context and digest used for each message. Record contexts and their
existing thread IDs retain their original wire format.

Rust uses `ConversationContext::Record(ConversationRecordContext)` or
`ConversationContext::Instance(ConversationInstanceContext)`; both inner types
implement `Into<ConversationContext>`. Supply that union to
`ConversationContentContext.context` and `conversation_thread_id`.
`peerwork_post` accepts the same explicit context through the shared native
tools. This source capability is not published SDK or production support.

The same candidate adds the read-only `structure.record.relations.read` action.
Select the original instance/protocol scope and an exact `record_id`/`revision`,
with optional `execution_context_id`, `cursor` and `limit` (maximum32). It returns
service-verified outgoing edges and selected target metadata, not target bodies.
Continue its opaque `next_cursor` under the same member and exact selector.
Target links retain their exact revision and current withdrawal state. This is
not an arbitrary JSON query, reverse graph or complete protocol-state export.
