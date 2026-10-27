# Deferred protocol event delivery and session routing

Status: design only. Instant delivery, automatic wakeup and session routing are
outside the current protocol-bundle and request/response implementation.

## Goal and boundaries

Deliver authorized Peerwork events to an explicitly selected Agent conversation
without asking the model to poll. Distinguish durable local receipt, submission
to the host, and an Agent's business response. A transport write is not proof of
reading, understanding or task completion. Delivery can be at least once;
business mutations retain stable operation identities and fencing.

The user installs/enables a supported integration. Peerwork must not silently
edit an Agent installation, project instructions or host configuration. Prompts
guide Agent choices; protocol rules enforce submitted actions. Closing an Agent
session does not magically leave a model running.

## Common implementation

Reuse one SDK-backed receiver with bounded incremental reads or a qualified
resumable event subscription. Persist the input checkpoint atomically with the
local outbox. Apply backpressure and bounded reconnect; notifications are wakeups,
not authoritative transaction outcomes. Do not replay all history on reconnect.
Validate current access before fetching selected content. Keys and E2EE body
opening remain on the Worker host. Persist ciphertext or protected metadata,
not plaintext copies in ordinary logs.

Each connector reports supported host versions, platform/runtime dependencies,
health, last input checkpoint, pending deliveries and sanitized failure reasons.
Provide installation, upgrade, disable/uninstall and end-to-end self-check flows.
Users should not need to write a listener or sign HTTP requests themselves.

## Multiple identities, sessions and workspaces

A credential profile is a long-lived identity. A host conversation is an
execution context, not a new cryptographic identity. Independent Workers should
use distinct identities when independent authority and attribution are needed.

Use explicit bindings containing service/authority, expected actor, credential
profile reference, workspace, instance/protocol package, role, subscription
scope, host installation and conversation ID. Model-facing tools select a short
binding ID; they do not accept arbitrary credential paths or silently fall back
to a recently used identity. An incoming event retains its binding throughout
subsequent replies and operation recovery.

One session may have several explicitly named bindings. Default selection is
allowed only when unambiguous. Different confidentiality domains should use
separate sessions: routing isolation does not prevent a model from mixing data
already placed in the same conversation. Switching bindings must not blend
incompatible role instructions or private contexts.

Separate event/checkpoint and delivery state by principal, subscription/filter
version and destination. Observe-only subscriptions may fan out. Executable work
uses one selected receiver or a consumer lease so multiple sessions of the same
identity do not all act on one notification. A local coordinator can serialize
necessary credential/journal writes without holding a global lock during network
waits. Cross-machine receiver ownership requires server/protocol lease arbitration;
a local mutex cannot establish distributed exclusivity.

Preserve uncertain operations during receiver failover. Resume their original
IDs before creating replacement business work. Session closure removes or
suspends that route; it does not delete the identity or workspace. Show the user
a connection table and explicit controls to bind, pause, move and remove routes.

## Codex

Provide MCP tools and a bootstrap skill for ordinary protocol access. Automatic
conversation delivery additionally requires an App Server bridge with an
explicit thread binding, authentication/approval handling and a supported
startup or connection flow. Send external events with their provenance; do not
silently turn untrusted peer content into high-priority user instructions.

Qualify idle delivery, busy-turn queuing, thread resume, process restart and
permission prompts separately. Do not claim a normal MCP plugin can control any
already-running CLI conversation. The official App Server exposes thread/start,
thread/resume and turn/start/steer; deployment support must be verified against
the selected host version.

Reference: https://learn.chatgpt.com/docs/app-server

## Claude Code

Provide a local stdio MCP Channel, protocol tools, a bootstrap skill and health
checks that distinguish a connected tool server from an active channel.
Declare claude/channel and emit notifications/claude/channel. Keep the session
open for delivery. Pin and test the MCP handshake/runtime combination.

Channels are in research preview. Custom channels are not automatically on the
approved allowlist even when distributed through a marketplace. Development
flags are for explicitly accepted local testing, not a general availability
claim. Official listing or an organization's allowedChannelPlugins policy must
be resolved for supported rollout. Document account/provider availability.

References:
- https://code.claude.com/docs/en/channels
- https://code.claude.com/docs/en/channels-reference

## Antigravity

Provide shared MCP tools/skill plus an App Sidecar receiving events. The Sidecar
is explicitly enabled and binds selected workspaces to conversation IDs. Use
agentapi send-message for existing conversations; creating conversations also
requires a selected project. Persist receiver state in the host-provided data
location and qualify host-managed restarts.

The referenced Sidecar capability is documented for Antigravity App. agy CLI
instant delivery is a separate compatibility question and must not inherit an
App support claim. Busy conversation semantics require actual host acceptance.

Reference: https://www.antigravity.google/docs/sidecars

## Acceptance before advertising delivery

1. Messages reach the intended conversation and identity, including multiple
   conversations, identities, workspaces and host installations on one machine.
2. Unknown or stale bindings cannot redirect content or credentials.
3. Quiet and busy sessions, disconnected hosts, restart and receiver failover
   have explicit outcomes; cancellation does not undo committed business actions.
4. Duplicate notifications do not produce duplicate business mutations.
5. Revoked access stops new reads and deliveries; no secrets/body text appear in
   routine diagnostics.
6. Measure transport and host-delivery latency independently of model response
   time. Establish actual SDK/host versions and platform support.
7. Use real Agent sessions for end-to-end acceptance. Scripted arithmetic or a
   successful write to a pipe does not establish Agent delivery or cooperation.

## Current work explicitly excludes

No Channel/Sidecar/App Server bridge, automatic background Agent invocation,
server push transport, distributed consumer group or multi-session message
router is implemented as part of the current non-delivery work. Protocol bundle
storage, full inspection, role instructions, SDK/CLI and actively invoked tools
remain independently useful and testable.

## Scope decision: MCP and host plugins are deferred

MCP is not required for the current protocol package/SDK contract. The current
implementation provides immutable protocol resources, full package inspection
and explicit role access through the service and SDK/CLI. A user can invoke these
from an existing Agent without a new connector. Build a thin MCP tool layer or
host plugin only when an actual integration requires it; neither is a prerequisite
for this delivery. No connector, push daemon or automatic environment edits are
included in this change.
