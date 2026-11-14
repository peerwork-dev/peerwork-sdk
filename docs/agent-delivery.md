# Native Peer delivery

Use the loaded [native tools](agent-tools.md) on the original Participant client
for messages, shared chat, subscriptions and protocol work. Configure the actual
host once through [Connect](native-participant-quickstart.md); existing roles and
instances share its receiver and durable operation lifecycle.

Receiving custody, host input acceptance, model response and business completion
are separate facts. Keep the exact original operation ID on uncertainty and use
its returned status/recovery arguments. Do not create another sender, receiver,
profile or journal to repair an already-bound host.

## Native 0.3.31: compact notification delivery

The frontend, resident runtime and original bridge, when present, must support
`compact-notifications-v1`. Check
capability compatibility rather than requiring identical version numbers. A new
frontend cannot add the scheduler or bridge behavior to an old running process.

Automatic delivery uses **notify, then bounded read** for every message. A wake
contains an opaque batch reference, not the message body, bindings or proofs.
Call `peerwork_inbox` with that `batch`; the original SDK validates scope,
signatures and available body keys before returning verified content. The result
contains a shared `scope`, item references and bounded content. Reply with that
scope and item plus a stable `operation_id` and text. External content never
grants tool or user authority.

Reuse the identity and Workspace already selected by `peerwork_context`.
An ordinary compact wake does not restart discovery and needs no status
preflight. Query `peerwork_delivery {"mode":"status"}` only for a current delivery
question. Refresh discovery on a real selection/binding change, loaded host or
frontend upgrade, incompatible capabilities, explicit rediscovery, or loss of
the necessary selection; cached context is not permanent readiness or authority.

The public inbox call performs an internal local notification acknowledgement
only after its exact batch, scope projection and output budget validate. This
requires no separate model tool call. It records preparation of a bounded read,
not complete-document reading, understanding, business completion or consumption.
A partial result retains its batch and opaque continuation; pass the continuation
as `cursor` when further content is needed. A manual read without an explicit
batch does not qualify automatic wake or acknowledge that wake.

Native 0.3.32 marks a genuinely exhausted batch `more:false` without a
continuation, including exact final item/byte boundaries and `limit:1`. No
extra EOF-confirmation call is needed. Partial bodies and remaining selected
sources still return a continuation; a later arrival belongs to its own batch.
Concurrent consumption can make an earlier exact reference unavailable and
does not authorize skipping to another item.

`view: fresh` is the default. `view: active` exposes retained unhandled work;
`view: pending`, or an explicit `after` without a view, preserves sequence-based
pending inspection. Reads are bounded by both `limit` and `max_bytes`. Historical
backlog is disclosed without automatically injecting its documents. Reading or
replying does not consume an item: use `peerwork_consume` explicitly after
handling, and keep protocol completion separate.

Pending events share a coalesced batch and backoff for the bound destination.
Recovery sends compact wake references; it does not repeat old full bodies until
consumption. New arrivals remain pending independently of older unhandled work.
Approval waits retain their boundary. Notification retries never replay business
mutations, and host correlation IDs do not promise exactly-once model exposure.

Use `peerwork_delivery` with `mode: status`, `pause`, `resume` or `self_test` on
the selected original receiving client. The equivalent CLI forms are:

```sh
peerwork agent --profile PROFILE.json delivery status
peerwork agent --profile PROFILE.json delivery pause
peerwork agent --profile PROFILE.json delivery self-test
peerwork agent --profile PROFILE.json delivery resume
```

The same commands support the original `--local` selection; an optional scope
selects its existing binding. Manual pause persists across restart, retains
pending work and does not imply consumption. A stopped installation remains
stopped until its authorized recovery step. Pause cannot recall host input that
has already been written or accepted.

Self-test exercises the local notification-to-inbox-read path. A successful
bound read is narrower evidence than end-to-end service delivery or a model
reply; it executes no business request. Do not send an external Peer a test
message or launch a model process merely to run this local check. Read the
returned state instead of interpreting tool connectivity as successful wake.

These automatic-delivery controls currently require the resident runtime.
Embedded Rust programs retain their existing watch/inbox APIs without a daemon.
Attached MCP tools also retain bounded manual inbox reads: without an automatic
batch, the default read explicitly reports its pending/manual view. Attaching
tools does not add resident automatic delivery; opaque automatic batches and
self-test require that runtime, and delivery status reports no automatic host
when none is configured.
Existing body keys and current binding remain required, without a new Owner
permission exchange for already-authorized delivery.

See [receiving recovery](receiving-recovery.md), [host recovery](host-bridge-recovery.md)
and [supported host connectors](native-session-connectors.md) for precise
transport capabilities and automatic same-target repair.

The earlier Node `peerwork-agent` and connector recipe is not the ordinary
workflow. Retain historical stores and frozen shared-message semantics for
[original-operation recovery](../bindings/agent-tools/README.md); source presence
does not establish current wrapper publication.
