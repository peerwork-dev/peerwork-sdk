# Protocol event delivery and session routing plan

Status: SDK 0.2.8 tool implementation prepared with real HTTP/native acceptance
and synthetic host adapter tests. Actual Agent usage is performed by the user's
selected Agents. Service discovery and release assets establish availability.
Playground remains on hold. See the [tool guide](agent-delivery.md).

## First delivery phase: Codex and agy

The first cohort is Codex and agy (provisionally Google Antigravity). Other hosts,
including Claude Code, remain later compatibility work. Support is qualified per
product surface and version; App support does not imply CLI/IDE support.

The product goal is IM-like Agent communication: when a selected route advertises
REALTIME_READY, every authorized message addressed to its agreed subscription
scope is expected to reach that Agent conversation promptly. Agents do not poll
or implement receiver/retry loops. SDK/API, CLI and host integrations share the
same message IDs, route bindings, delivery state and recovery contract. The
connector owns background receipt and host delivery, with explicit user enablement.

### Peer-visible reachability

Reachability belongs to a route (actor, workspace/subscription, destination
conversation), not to a global identity. Authorized peers can inspect it.

| State | Meaning |
| --- | --- |
| TOOL_ONLY | Explicit SDK/CLI access; automatic conversation delivery is unavailable |
| REALTIME_READY | Qualified receiver and destination are live, current access is valid, and the route can meet its advertised host-delivery deadline |
| DELAYED | Disconnected, backlogged, awaiting a host boundary/approval, or otherwise unable to meet that deadline; queued messages remain recoverable |
| OFFLINE | No current receiver lease or route is paused/closed |

IDLE/BUSY/WAITING_APPROVAL is a separate execution state. BUSY can remain
REALTIME_READY only if the qualified host can accept messages into that running
conversation within the deadline. Waiting for the next voluntary tool call does
not qualify. Availability expires using service time and is renewed by the
receiver. Renewals attest both transport and destination readiness; a heartbeat
from an unrelated daemon cannot keep a dead conversation online. Routing epochs
fence replaced receivers and late acknowledgements.

Readiness qualification must demonstrate that an incoming message can wake an
idle Agent or enter an active Agent's supported live-input path. A route that
only stores messages until some later turn cannot advertise this state. Expose
execution blockage and measure first Agent activity/response separately from
transport and host acknowledgements; model response duration is not guaranteed
by a connection lease.

### Delivery promise and receipts

Acceptance atomically persists a message and its delivery obligation. Live push
wakes the receiver; bounded cursor recovery repairs gaps. Every in-scope message
is tracked, including ordinary discussion messages, rather than only selected
task events. Directed delivery and explicitly selected fan-out are distinct;
"all messages" does not grant access to unrelated spaces or conversations.

Track ACCEPTED, CONNECTOR_RECEIVED, HOST_ACCEPTED, and DELAYED/FAILED/UNCERTAIN
separately. HOST_ACCEPTED identifies the intended host conversation and host
acknowledgement; it does not claim the model read, understood or answered the
message. Record an Agent response separately. A host that only acknowledges an
internal queue cannot prove model-visible delivery from that acknowledgement.

Freeze a measured host-delivery deadline during host qualification. A proposed
initial healthy-route target is p95 <=2 seconds and p99 <=5 seconds, not a shipped
SLA or a model-response deadline. Missing the advertised deadline must produce a
visible delayed/uncertain outcome and downgrade readiness. Network failure can
occur immediately after any heartbeat: never silently preserve a "real-time
delivered" claim or indefinitely hide it behind PENDING.

Use a durable backend outbox plus a resumable notification stream. The SDK owns
checkpointing, bounded reconnect, deduplication, acknowledgements and backpressure;
host connectors only adapt the qualified conversation API. Keep notifications
and plaintext/E2EE content selection separate. Do not replay complete workspace
history on reconnect. Host acknowledgements lost after acceptance need explicit
reconciliation; blindly sending a fresh model turn can duplicate work.

First acceptance is a real Codex-to-agy round trip, then idle/busy delivery,
disconnect/restart, deadline downgrade, duplicate recovery, revocation and
multiple identities/sessions/spaces. Do not advertise REALTIME_READY on a host
surface until those cases pass. This phase does not implement a playground,
benchmark, new model harness or arbitrary control of existing user sessions.

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

Reuse existing SDK/CLI protocol access. Package MCP tools or a bootstrap skill
only where the qualified host integration needs them. Automatic conversation
delivery requires an App Server bridge with an
explicit thread binding, authentication/approval handling and a supported
startup or connection flow. Send external events with their provenance; do not
silently turn untrusted peer content into high-priority user instructions.

Qualify idle delivery, active-turn steering/queuing, thread resume, process restart and
permission prompts separately. Do not claim a normal MCP plugin can control any
already-running CLI conversation. The official App Server exposes thread/start,
thread/resume and turn/start/steer; deployment support must be verified against
the selected host version.

The current official contract supports `turn/steer` with an `expectedTurnId` for
an active turn; it fails if there is no matching active turn. Qualify the idle to
busy race and retained message identity. Existing standalone CLI conversations
are not automatically accessible through an independently started App Server.

Reference: https://learn.chatgpt.com/docs/app-server

## Later compatibility: Claude Code

Outside the first Codex/agy cohort. Requalify its supported message/channel
interface and account/plugin availability before selecting an integration.

## Antigravity

Reuse SDK/CLI access and provide an App Sidecar receiving events. The Sidecar
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

## Implementation boundary

The first tools implement a resumable notification stream, native signed route
control and receipts, a common SDK-backed receiver, Codex App Server adaptation
and agy CLI IDLE_ONLY adaptation. They do not run real Agents for acceptance,
change user host configuration, supply a playground or claim model-response
latency. Antigravity App Sidecar host acceptance and other host surfaces remain
unqualified. A normal MCP tool server does not establish live delivery.
