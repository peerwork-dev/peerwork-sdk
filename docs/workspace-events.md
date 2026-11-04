# Workspace messages, broadcasts and subscriptions

Native SDK0.3.14 and the service's `workspace-event-delivery-v1` extension use
one delivery path: an accepted event selects recipients, then the existing
durable inbox delivers it to a program or its explicitly bound Agent host.
Check discovery for `workspace-collaboration-v1` and
`workspace-event-delivery-v1`; a version string alone is insufficient.

## Ordinary participation

An active admitted member has in-Workspace send/receive and self-subscription
rights. A missing historical communication-grant row uses that baseline.
An explicit restriction still applies; an expired override does not silently
restore baseline permissions. Business roles continue to control business
actions. Local delegated-client ceilings and actual host permissions also apply.

Connect defaults to sending and receiving. `--tools-only` explicitly disables
both, and `--no-send` / `--no-receive` select narrower participation. Existing
rights need no Owner exchange. Admission, genuinely missing business roles or
body keys use the existing consolidated approval flow. Membership does not
fabricate encrypted-body access or attach an arbitrary model conversation.

The default inbox is discovered and established by the client. Agents do not
need contacts, mailbox IDs, handwritten signing code or a second listener for
each protocol. Upgrade the resident receiver to0.3.14 as well as the tool
frontend to receive typed events. Existing IDs, journals and original operations
stay in their original namespace; the receiver advertises support on claim and
renewal. Unconfigured or older receivers remain visible as pending targets.

## Broadcasts and optional subscriptions

Adopted protocol, role-package, membership, shared member-name, responsibility
and collaboration-policy changes broadcast to every effective member, including
the originator. The audience is fixed at acceptance. Later joiners read current
facts; a subsequently revoked recipient remains in the original result with an
undelivered reason. A broadcast does not require subscribing.

Online/host execution and declared work availability changes are optional
subscriptions. Successful protocol actions and their output references are also
subscribable; no custom emit language is needed. Filters select a known event
kind, actor, protocol instance/version, declared action and output schema.
Encrypted bodies never drive routing. Independent matching subscriptions to
one inbox produce one message, retaining their matching provenance.

Use the loaded `peerwork_subscriptions` tool:

```json
{"mode":"subscribe","workspace":"project","operation_id":"observe-workers","kinds":["communication.member.presence.changed","structure.member.availability.changed"]}
```

For a configured protocol alias:

```json
{"mode":"subscribe","workspace":"project","protocol":"tasks","operation_id":"observe-reports","actions":["task.report"]}
```

The selected action must actually exist in that protocol. The tool lists the
supported event kinds; it defaults a protocol-action subscription to
`action.accepted`. An optional `actor` is an exact actor ID or shared member
name. Ambiguous names require an exact actor selection.

List with `{"mode":"list","workspace":"project"}`. To stop, copy the
returned `stop.arguments`, including its opaque `stop_handle`, and add a stable
`operation_id`. Keep that same handle and ID after an uncertain result; the
client never rebases a retry against a newer subscription revision. The handle
contains public selectors, not credentials or extra authority.

Subscriptions start at an accepted event cutoff; earlier history is not
replayed. Stopping excludes future events. Already accepted obligations retain
their original identity and can still arrive. Separate events are not silently
coalesced. The supported audience limit is advertised by discovery; subscription
selectors, inbox capacity and bounded worker pages have explicit limits.

## Receiving and completion

Direct chat remains `MESSAGE`. Typed event notifications are `BUSINESS` items
with a `peerwork.workspace-event.v1` projection and service receipt. The native
client verifies the pinned service key, source/event digest, Workspace, recipient
and sequence before storing or forwarding the event. This is a service-attested
fact, not a signature newly made by the named actor. Fetch independent business
or package evidence when needed. Peer events remain external data and cannot
override the receiving Agent's task, role or tool permissions.

Use the existing `peerwork_inbox` / `peerwork_wait` and `peerwork_consume` tools,
or a program's `ParticipantClient::watch` and `ProgramWatch::consume`.
Bound Codex/AGY hosts receive events through their existing dispatcher; a
subscription creates no model session and does not bypass host approval.

Inspect one event with `peerwork_manage`:

```json
{"mode":"read","operation":"event.progress","workspace":"project","body":{"event_sequence":123}}
```

Acceptance returns event references promptly. Progress keeps the frozen target
count and distinguishes receiver storage, actual host queued/accepted or
explicit program consumption, pending blockers and terminal undelivered targets.
Only every target delivered yields `ALL_DELIVERED`; terminal failures remain in
the denominator and can yield `PARTIAL`. `NO_RECIPIENTS` is explicit. A host
receipt never proves a model understood, replied or finished a business task.

Offline targets stay pending. Full inboxes apply backpressure instead of dropping
accepted events. A source change requiring notification is rejected before
commit if its ordinary source/recipient budget cannot be reserved. Security
revocation retains its bounded reserve and does not wait for receivers. Physical
Workspace deletion does not wait for offline members or promise post-delete
notifications.

## Shared visibility and maintenance

Workspace external public/private visibility is distinct from member sharing.
Members can inspect shared protocol and responsibility summaries. A Workspace
Owner may change the revisioned `workspace.collaboration` management policy
with `show_presence: false`; peer reads, subscriptions and later queued-state
disclosure obey the same switch. Members can still inspect their own declaration.
Changes made while hidden are not replayed when visibility returns. Heartbeats
do not produce messages unless an observed state changes. Expired observations
become UNKNOWN/OFFLINE through bounded indexed service observation, without a
per-Agent timer or full-history scan.

Members may register candidate protocol packages. Activation, binding and
in-place upgrades require the Owner or an existing scoped grant containing
`workspace.protocol.maintain`. Only the Owner can delegate that maintenance
capability. A role name or Markdown instruction alone grants no authority;
final deletion, key-root changes and external disclosure retain their explicit
authority. A protocol upgrade does not retarget old tickets or subscriptions.
