# Participant SDK and resident runtime candidate

**Unreleased source candidate.** SDK 0.2.16 and Agent tools 0.1.0 do not ship
this interface. Native mail and automatic program watch are implemented in this
candidate; this document does not announce production availability, new host
connectors or a qualified cross-platform release.

The native candidate is versioned 0.3.0. It selects Linux x86_64 GNU/glibc2.28,
macOS ARM64 and Windows x86_64; optional language-binding packages are not part
of this native release cohort. Candidate CI installation and dependency checks
do not by themselves announce a published release or production availability.

## Shared engine

A program participant binds an explicit identity, service Origin and protected
state namespace. It does not need an Agent profile or existing protocol instance.
Rust applications embed `participant::ParticipantClient`; other applications
can use the same engine through `communication_runtime` and bounded local JSONL.
Neither candidate client path requires Node or Python. The service and synthetic
HTTP test fixture retain their existing server dependencies.

`ParticipantClient::open` establishes local ownership and may succeed offline.
It does not prove network or host connectivity. One owner holds the state and
journal namespace; another embedded client/runtime cannot open those same
namespaces concurrently. Stop old consumers explicitly before state takeover.
An optional configured `authority` pins an existing authority digest at this
root. Default authority remains SHA256(actor ID). The private owner binding
prevents changing identity, Origin or authority while reusing this state;
requests cannot override it.

Public async calls use channels to a single owned engine thread. The engine
multiplexes native futures, shares the verified discovery/time anchor and HTTP
pool, and bounds real work independently of how many callers are waiting.
No SQLite transaction is held across network awaits.

Explicit resident sessions keep at most two idle WAL connections: one native
journal and an optional existing body-key store. Actual calls still open and
validate their protected stores and select current keys. The keepers never
serve authorization, business rows or key material, create/migrate databases,
or hold a read/write transaction; an unavailable optional keeper does not block
an unrelated structure read. `metrics().http.resident_databases` reports only
whether those handles currently exist. FULL synchronous commits and the default
automatic WAL checkpoints remain enabled. After owned work stops, engine close
awaits the keepers' normal final checkpoint/close before releasing ownership.

## Program contract implemented so far

### Explicit physical-session replacement

The candidate exposes `participant_rebind::rebind_host(config_path, request)`
and `peerwork runtime rebind-host /absolute/runtime.json /absolute/request.json`.
Stop the owning runtime and embedded clients first. The protected request is:

```json
{
  "format": "peerwork.host-rebind.v1",
  "operation_id": "replace-worker-session-1",
  "engine": "worker-identity",
  "host": "worker-session",
  "adapter": {
    "kind": "codex",
    "endpoint": "unix:///absolute/selected-app-server.sock",
    "thread_id": "explicit-existing-thread",
    "expected_session_id": "explicit-existing-session"
  }
}
```

The selection addresses one configured host group and one identity/Origin
engine, with at most eight existing mailbox subscriptions. A host shared by
different engines or duplicated across equivalent host entries must first be
selected as an unambiguous group; the command refuses that selection before
claiming a mailbox. Normal runtime operation still supports multiple identities.

One call validates the existing target adapter and each scoped bridge grant,
flushes original pending host reports, and signs an exact same-device replacement
for each selected mailbox. It then commits durable local binding history and
the target host descriptor, and atomically updates the runtime configuration.
The original identity, receiver keys, inbox cursors, messages and host-call facts
are retained. An unknown old input stays at its original binding and is never
re-injected into the replacement session. This operation performs indexed
selected lookups and internally drains bounded local pages; it does not replay
workspace history or start a replacement model process.

The sealed job records each original claim before submission. On interruption,
repeat the same command with the same request and `operation_id`; a missing
response cannot justify a fresh claim. A versioned engine-owner fence prevents
the ordinary engine, transfer and unsupported older readers from starting
during partial replacement. Unrelated configuration edits are refused rather
than overwritten. A completed retry returns its historical result before
opening the engine or contacting a host, preserving later work.

A definitive remote refusal is not transport uncertainty. The candidate retains
the original job and fence on that refusal. An explicit operator can call
`participant_rebind::recover_host_rebind` or
`peerwork runtime recover-host-rebind /absolute/runtime.json /absolute/request.json /absolute/recovery.json`.
The protected recovery file is:

```json
{
  "format": "peerwork.host-rebind-recovery.v1",
  "decision_id": "retry-after-fixing-access-1",
  "action": "RETRY_REJECTED"
}
```

Use a stable `decision_id` for each explicit decision and repeat it after
interruption. Reusing that ID with a different action is refused. Recovery
checks the original journal's exact signed request and digest-bound service
receipt locally; an HTTP status, missing response or current mailbox snapshot
cannot prove a replacement had no effect.

- `RETRY_REJECTED` assigns a new claim ID only to a verified
  `REJECTED_NO_EFFECT` attempt. Its original packet and receipt remain in the
  journal and its digest is retained by the sealed job. Confirmed subscriptions
  are preserved; unknown claims keep their original IDs. If the same original
  receiver/destination has a newer epoch, the explicit retry may refresh only
  that epoch after a verified selected read. It cannot change identity,
  membership, receiver key, binding version or selected target.
- `ABORT` is allowed only if every frozen replacement is locally proven not
  submitted or has a verified no-effect receipt, and none has committed. It
  verifies the original mailbox binding, closes its old lease, restores each
  saved watch's enabled/disabled state, then releases the maintenance fence.
  `HOST_REBIND_ABORTED` retains the original configuration, keys, cursors and
  uncertain original host calls. Its destination digest describes the attempted
  target, not a live current binding. It does not cancel old model work or
  remove peer messages.

Unknown replacement outcomes refuse both cancellation and fresh claim IDs;
resume the original `rebind-host` operation to reconcile them. A partially
committed multi-mailbox replacement refuses rollback and must finish forward.
Retry decisions are bounded at16 per job; abort retains its own terminal slot.
The sealed job payload remains capped at512KiB. Definitive refusals require repairing their
cause before another explicit retry. Completed or aborted observations do not
overwrite later engine/configuration writes.

`HOST_REBIND_READY` means local binding/configuration commit completed. Start
the runtime normally to observe current receiver/host readiness. It does not
attest model execution, cancel old model work or establish IM performance.
The service must advertise `native-mailbox-rebind-v1`; existing production
availability and cross-platform qualification are not implied by this guide.

| Entry | Candidate behavior |
| --- | --- |
| `ParticipantClient::open` | Validate explicit actor, Origin, identity and state ownership; no implicit identity creation. |
| `restrict(name, capability)` | Derive an isolated operation namespace with a subset of local authority. Backend authorization still applies. |
| `invoke(request, wait_budget)` | Authorize and durably admit a supported structure mutation, then optionally observe its result. |
| `request(request)` | Perform an authorized selected read or ephemeral control operation. |
| `operation(id)` / `operations(after, limit)` | Observe local durable operations in this client namespace; keyset pages contain at most 32 items. |
| `operation_result(id, selection)` | Read a bounded chunk from one authorized operation outcome; re-verify the original native response when the index contains only a summary. No remote submission or history read. |
| `recover(id)` | Schedule recovery of that original operation without replacing its immutable input. |
| `watch(options)` | Durably configure an exact mailbox/generation and stable consumer; share the engine-owned SSE/lease/ACK driver. |
| `watch_bindings()` | Read enabled, authorized mailbox bindings in this client namespace; no remote call or replacement lease. |
| `ProgramWatch::next()` / `inbox(options, after, limit)` | Receive coalesced notifications and a bounded verified local snapshot, without a remote page read. |
| `consume(options, references)` | Persist explicit local application consumption and automatically upload its fenced ACK. |
| `delivery_status(options, reference)` | Select local receiver host evidence and independent upload state; never repeat a host input. |
| `unwatch(options)` / `ProgramWatch::stop()` | Pause durable reception/renewals; retain messages, claims and unknown-operation recovery data. |
| `metrics()` | Observe engine bounds, cumulative HTTP counters and bounded local phase timers. |
| `close()` | Owner-only shutdown; cancel and await owned work before releasing state locks. |

The native operation catalog lives in `peerwork_core::structure_execution`;
local convenience operations live in `participant_actions`. This finite catalog
does not promise that a service deployment advertises every optional capability.
Lifecycle, protocol, record and publication operations use the native catalog.
Approval, key handoff/rotation and selected-record publication also have the
conveniences described below. Explicit migration uses configured source handles;
offline fixture/plan/simulation runs locally without an online apply path.
Native mail construction and selected reads are implemented in
source, together with automatic durable program `watch` and local notification
waiting. Native Agent CLI/MCP tools provide bounded local inbox waiting and
share this engine. Existing-session host adapters remain candidate code;
actual-host, first-use and cross-platform release qualification are pending.
General business-predicate waits are not implemented. Do not build production
automation against this candidate.

The source example `crates/runtime/examples/participant_program.rs` loads one
protected `communication_runtime::EngineConfig`, creates a PRIVATE workspace
with a stable operation ID and reads its metadata. It uses no connector or Agent
profile. The example must own its state; stop it before giving that state to a
resident runtime.

## Admission, continuation and recovery

Validate syntax and local authority before admission. Capacity checking and
durable reservation are atomic. `NOT_ADMITTED_CAPACITY` creates no new operation;
an older operation is never reclassified by a failed new invocation.

An admitted operation has immutable input and a stable operation ID. Repeating
that ID with identical input observes the original operation; different input
returns `OPERATION_INPUT_CONFLICT`. The native journal freezes signing/encryption
choices and reconciles the original command after a lost acceptance response.
Closing a tool connection or exhausting the caller's wait budget does not cancel
admitted work. Stopping the engine ends active execution and leaves exact durable
recovery state for reopening.

The scheduler reads/decrypts a selected queued request once and retains that
validated value for execution. After a successful outcome transaction commits,
the local caller receives the exact value that was encrypted and written,
without an immediate read/decrypt of its own new write. Selected reads and
restarts still authenticate persisted input and outcome bytes; durable admission,
the running marker, signed-packet storage and outcome commits remain unchanged.

`ADMITTED`, `RUNNING`, `PENDING` and `BLOCKED` are local execution observations.
They are not recipient or model evidence. Service acceptance and business
completion remain distinct; follow the operation's effect certainty and original
outcome. A committed operation awaiting key delivery remains `COMMITTED` even
while its local work is pending. Generic HTTP failures do not prove no effect.

Defaults are 4 foreground operations and 64 pending mutations, with one separate
bounded prerequisite refresh task. Maintenance runs at most one active operation
and ordinary queued work has priority. Pending verified results awaiting local
persistence continue occupying their slots. Shutdown tracks all owned tasks.

Protected queue storage defaults to a 32 MiB logical allocation limit; configuration
allows up to 48 MiB, 1,024 pending mutations and 32 foreground operations. Each
pending operation reserves outcome capacity before starting. The index also has
a 65,536-row bound. Terminal metadata remains for deduplication; there is no
automatic pruning. Large verified outcomes retain a bounded local summary and a
native-journal reference. `operation_result` accesses those selected details.

## Management conveniences and coverage

Use the same `Invoke`, local capability and operation namespace for these local
names; they are not additional service actions. Put workspace/instance/protocol
selectors in `scope`, never in `body`. Native schemas reject unknown helper
fields. Idempotency is derived from the original participant operation ID and
namespace; callers cannot supply a second native command ID or idempotency key.

| Capability | Entry | Behavior / boundary |
| --- | --- | --- |
| Workspace lifecycle, membership, grants, deletion | Native catalog through `invoke` / `request` | Explicit backend authorization and CAS remain required; new spaces default PRIVATE. |
| Device/browser access request | `request` with `participant.access.request` | Body: `label`, optional `kind` and selected `write`. Returns a signed, expiring request and creates only protected local recipient state. |
| Owner approval and key delivery | `invoke` with `participant.access.approve` | Body: `request_jws` and native approval options (`mode`, `ttl_ms`, `deliver_content_keys`, `follow_current_key`, `include_history`, `key_ids`, `selected_write`). Optional workspace CAS goes in `expected_workspace_revision`. Uses the existing encrypted ACCESS parent and original signed packet. |
| Selected key import | `request` with `participant.keys.accept` | Body: `owner_id`, explicit `key_ids`, optional `current_key_id` / `expected_current_key_id`. Verifies grants before local import; never guesses a key or grants membership. |
| Local key initialization | `request` with `participant.keys.initialize` | Empty body. Works offline, returns `LOCAL_ONLY` and `remote_access: NOT_GRANTED`; does not publish or rotate the service head. |
| Owner rotation | `invoke` with `participant.keys.rotate` | Empty body. Uses existing durable native head publication and bounded recipient-delivery stages. |
| Owner delivery coordination | `invoke` with `participant.keys.coordinate` | Empty body. Resumes persisted native stages; does not enumerate business history. |
| Protocol inspect/register/bind/adopt and business action | Native catalog | Declared business actions remain data, not new handwritten SDK methods. |
| Record selection/withdrawal and publication policy/withdrawal | Native catalog | Preserve selected revisions, explicit disclosure and service permissions. |
| Publish one selected record | `invoke` with `participant.publication.publish` | Instance scope required. Body: `record_id`, `revision`, `title`, `disclosure: PUBLISH_SELECTED_CONTENT`, `body: {from: RECORD}` or explicit `{from: TEXT, text: ...}`, optional `expected_publication_revision`. Reuses the encrypted PUBLICATION parent and exact signed packet. |
| Mailboxes/messages/subscriptions/watch | Native catalog and watch API | Separate receiver custody, application consumption and participant reply. |
| Explicit archive conversion | `participant.archive.sources` / `participant.archive.migrate` | Administrator-configured source handles; existing native preparation/upload/staging/recovery. No request-supplied local paths. |
| Offline protocol workbench | `request` with `participant.protocol.offline` | Explicit caller-supplied fixtures, simulation, plan and compatibility inspection. Always non-authoritative; no retired export/apply or file/profile access. |

A workspace-scoped credential may receive explicitly granted management helper
authority; an instance-scoped Worker cannot approve workspace access or rotate
keys. Helpers do not silently expand authority. Service-side Owner checks remain
authoritative. Runtime client tokens cannot select a different identity or local
source directory. Successful key import and local initialization are local facts,
not evidence that another participant can decrypt or that a host is connected.

## Explicit archive migration

The engine administrator configures at most eight `migration_sources` in
`EngineConfig` / `ParticipantConfig`. Supported descriptors are:

```json
{"kind":"CHECKPOINT","workspace_id":"WORKSPACE_ID","path":"/owned/checkpoint.jsonl","sha256":"FILE_SHA256"}
```

```json
{"kind":"LEGACY_CACHE","workspace_id":"WORKSPACE_ID","state_directory":"/owned/legacy-owner","plan_path":null}
```

Paths must be absolute and all native private-file/signature/source validation
still applies. `CHECKPOINT` imports exactly that Owner-signed artifact, pinned to
its configured file hash; the checkpoint determines its name. `LEGACY_CACHE`
uses the existing native read-only-snapshot preparation with an optional explicit
mapping plan. Neither silently restores executable business workflows or changes
identity. Retired legacy online readers remain unavailable.

Use `request` with `participant.archive.sources`, workspace scope and an empty
body to obtain opaque source IDs and kinds without local paths. Each ID hashes
the entire descriptor: changing workspace, path, selected plan or expected file
hash creates a different ID. Submit `invoke` with `participant.archive.migrate`
and body `{source_id}`. `name` is optional only for cache preparation; it cannot
rename an already signed checkpoint. The native operation remains Owner-authorized.
An instance-scoped Worker cannot acquire this authority.

New admission requires an exact configured descriptor. A missing handle creates
no reservation. Once native preparation is persisted, recovery uses its original
encrypted selection/packet before looking for new source configuration. Removing
a source does not retarget an old operation or erase its committed outcome.
An admitted operation interrupted before native preparation needs its original
descriptor restored. Never change IDs to resolve an unknown remote result.

One counted maintenance worker runs checkpoint/conversion CPU and local IO away
from the SSE/lease owner. Shutdown cancels and awaits it before releasing state
ownership, including its lazily created native executor. Backend staging and
source-frontier checks remain unchanged. A completed result can be observed
after the input file disappears; it does not initiate another import.

## Offline protocol tools

`request` with `participant.protocol.offline` uses root scope and body
`{operation, input}`. Allowed operations are `fixture`, `simulate`, `plan` and
`compatibility`; execution delegates to the existing native protocol workbench.
The existing `protocol_workbench::workbench_json` is also available to Rust
programs without opening an identity/participant engine.

The shared-engine entry uses its counted worker limit and ordinary input bound;
CPU work runs off the SSE owner. It reads only caller-provided JSON. Results
carry `OFFLINE_RESULT`, `authoritative: false` and simulation provenance, never a
service receipt or evidence of actual business acceptance. They do not certify
production field policy, permissions, transport or host delivery. Fixture
assumptions and unsupported evaluator features remain visible in the workbench
result. `export` and `apply` are rejected at this entry, and no `profile`, identity
path or source directory can be used to revive a retired online flow. The engine
may independently refresh its normal service prerequisites; offline work does
not depend on those requests succeeding.

## Selected durable result access

Call `operation_result` (or local IPC `method: operation_result`) with an original
operation ID and `selection: {pointer, offset, limit, expected_sha256}`. `pointer`
is a JSON Pointer in the outcome, for example `/result/structure/author_intent`;
the default empty pointer selects the entire outcome. Limits are 1–65,536 bytes
per chunk and 32 MiB per selected value. The returned `data` is base64url of a
slice of the selected value's JSON UTF-8 encoding, so UTF-8 characters can cross
chunk boundaries safely. Concatenate/decode the bytes before parsing JSON.

The first chunk returns `sha256`, `total_bytes` and `next_offset`. Continuation
requires that digest. `RESULT_CHANGED` means the selected snapshot is different;
the original operation remains intact. A cache of at most eight selected values
and 32 MiB reuses verification/serialization for continuation chunks. On eviction
or process restart, only the selected original response is re-verified; no remote
read, submission or full-history traversal occurs. Verification runs in counted
blocking work so it does not stall the SSE/lease driver. Metrics distinguish
cache preparations and hits.

`LOCAL_DURABLE_OUTCOME` selects the encrypted engine outcome. For an oversized
summary, `VERIFIED_NATIVE_COMMAND_RESULT` selects the original packet-bound native
result, including cached selected body opening. This historical command result
is distinct from any later convenience-operation continuation status. The
operation's known effect certainty survives result-selection or verification
errors. Requests cannot use arbitrary command IDs, another client namespace,
or local file paths to bypass original-operation authorization.

## Native mail source candidate

Native mail uses `native-mailbox-v1`, independently of task instances. The Owner
first grants send/receive rights to exact membership generations. Discovery of
addresses, explicit mailbox claim and pulse use the same operation catalog.
A communication grant does not deliver body keys or grant business actions.

`Invoke::plaintext_message` accepts UTF-8 text up to 65,536 bytes, together with
`structure.message.send` and `content: { "mode": "WORKSPACE_E2EE" }`. Do not also
supply a ciphertext body. Supply a conversation ID, explicit recipient
`{mailbox_id, membership_id}` addresses, and optionally the sender's selected
`reply_address`. A reply pins the prior message in `reply_to`; it uses the
original signed reply address or an explicit destination, never a guessed session.

The SDK binds workspace/actor/original command, conversation, reply fields and
ordered recipient generations in a distinct message AAD. It reuses the existing
protected workspace key store. Exact ciphertext is elected and journaled before
submission. Warm sends can reuse a previously verified selected key and time
anchor without a head-read request. This is not a claim that the remote head is
unchanged: a signed `CONTENT_KEY_STALE` rejection invalidates only that local
selection. The original rejected message remains terminal and immutable; a new
operation synchronizes the selected head. Historical body keys are retained.
Local follow-up warnings do not erase the independently verified service outcome.

`structure.message.get` and `structure.mailbox.inbox.read` verify the original
sender command, message/delivery IDs, workspace and selected recipient generation.
The result's local `opened_messages` reports `OPENED`, `KEY_UNAVAILABLE`,
`AUTHENTICATION_FAILED`, `BODY_INVALID`, `KEY_STATE_INVALID` or a source-reference
state separately from structural verification. Missing keys never downgrade to
plaintext. SOURCE messages require separately authorized exact record access.

The core also verifies signed stream grants and full SSE frames, including both
data/control digests, receiver/destination binding, cursor monotonicity, the
mailbox frontier and independent original business/control commit proofs.
A private local inbox module atomically persists encrypted original frame
proofs, terminal projections and both cursors. Storage ACK and explicit
application consumption have separate pending upload state. Empty progress
proofs are compacted; confirmed consumption retires only completed local cache
entries, preserving a bounded retry receipt window. Service-retained messages
are not deleted. Withdrawal watermarks retire only after the signed mailbox
frontier is passed and no relevant pending source remains. Projection and
retirement use bounded indexed selection, not history-wide updates.

`watch` now owns the automatic receive path. One identity/Origin engine merges
up to eight mailbox scopes into one SSE connection and independently bounds
at most eight actual control requests, including requests stopping after
`unwatch`. The foreground operation limit is separate. Only two verified frames
can queue for persistence, and a stream advances its local cursor only after the
owner confirms the atomic commit. Scope changes fence queued old-stream frames
with a local generation. The initial service-signed frame proves the selected
receive path even when the mailbox has no data; unsigned `ready` is insufficient.

`ProgramWatch::next()` returns `WatchSnapshot`, which may include up to 32
unconsumed entries after either a data or connection/ACK state change. Notifications
are coalesced. Deduplicate by delivery ID when an application can fail between
processing and explicit consumption. Use `next_after` for additional local pages.
`receiver_ack_pending` and `application_ack_pending` describe distinct upload
queues. `consume` confirms local durable intent; it does not claim that remote
upload or business work has completed. Successful remote ACK observations wake
watchers independently of message reception. Message opening uses protected
cached keys, including while offline; key delivery/approval convenience integration
remains pending.

`receiver_link_verified` and `RECEIVER_LINK_VERIFIED` prove only the service to
receiver path. They do not prove a selected Agent host session or model response.
Normal EOF, token renewal, scope replacement, network failure and task failure
revoke current connection readiness. `disconnects` retains the observation even
if coalescing hides a short intermediate state. Current mailbox fences and
bounded retry/backoff remain owned by the engine. A single revoked/expired/fenced
scope is revalidated independently and cannot permanently block healthy scopes.
A confirmed no-effect heartbeat outside its issuance window refreshes nonce-bound
service time once before retrying the same fence. The browser/system wall clock
never supplies authorization time.

Mailbox claims use an independent receiver device key retained encrypted in the
inbox. The actor's signing key alone cannot adopt another initialized receiver.
The inner continuity proof binds the service audience, actor, workspace, mailbox,
receiver, destination, expected epoch, replacement flag and `claim_command_id`;
the service requires that ID to equal the outer command. A refused proof cannot
be reused under a new command after lease expiry. Exact original-command retry
returns its original refusal or acceptance. Claims add no per-message proof or
history scan. The authorized mailbox view exposes the receiver public key.

Expired custody does not authorize replacing lost call evidence. A fresh state
root targeting an initialized mailbox is blocked with
`MAILBOX_STATE_RECOVERY_REQUIRED`; restore or explicitly transfer the original
receiver state. Missing local receiver keys return
`RECEIVER_CONTINUITY_KEY_MISSING` and `RESTORE_ORIGINAL_RECEIVER_STATE`, without
creating a new receiver. This is a cooperating-client continuity rule, not a
security boundary against someone who can copy all protected local secrets.
For low-level explicit `structure.mailbox.claim` calls, prepare the device proof
for `body.claim_command_id`; Participant selects that same native command ID.
Ordinary programs use `watch` and do not construct or sign these claims.

Dropping a notification handle leaves durable reception and recovery running.
Explicit `unwatch` stops local dispatch and renewals; its last remote lease expires
within 15 seconds. It does not delete service messages or original claims. Reattach
the same binding to resume. A consumer ID identifies a stable program endpoint;
do not use a generic program label as proof of an actual Agent host session.
Selected host dispatch is integrated below. Safe rebind, old-call takeover and real Agent-host qualification remain pending.
A verified signed no-effect BUSY claim may advance the next durable claim ID
for the same original receiver. An unknown outcome retains its exact ID/packet.
A foreign receiver remains blocked after lease expiry; a new ID does not grant
custody of another receiver's uncertain calls.

Paused descriptors are bounded to 256 retained bindings, with eight enabled
scopes. Their original receiver and claim identity are retained. Invalid persisted
recovery data reports an explicit error while unrelated SDK operations remain
usable. This candidate does not import old Node receiver state automatically.

## Selected existing-session dispatch

A fresh watch that finds another receiver's live lease waits with
`MAILBOX_RECEIVER_BUSY` and bounded backoff; it does not repeatedly submit new
claims or force replacement. If a race produces a verified, service-signed
`REJECTED_NO_EFFECT` BUSY result for the frozen claim, the engine atomically
advances only the next claim selection. The original packet/result stays in the
native journal. Receiver, namespace, membership, mailbox and destination remain
unchanged; inspection supplies the current epoch and the next claim still uses
`replace=false`. That selection survives restart. Unknown, unsigned or failed
observations never authorize advancing the original claim. A late refusal after
local stop is retained for verification on reattach. This is lease contention
recovery, not transfer of an uncertain external host input to a new session.

`RuntimeConfig.hosts` is an optional administrator-owned list. Each entry has
`name`, `adapter` and `subscriptions`; each subscription selects a configured
`client` and exact `WatchOptions`. Up to eight host configurations and eight
subscriptions per grouped target are admitted. Identical adapter selections
share one dispatcher, with duplicate subscriptions removed. This grouping is
within the resident runtime; cross-runtime host ownership is not yet qualified.
Worker requests cannot change the adapter, create a host call or submit host
receipts through JSONL.

The Codex adapter selects an existing `thread_id` and `endpoint`, optionally
`expected_session_id`. Unix control sockets use WebSocket Upgrade. It discovers
and pins the actual session before configuring host-bound reception, initializes
once per connection and resumes that exact thread without model, sandbox,
approval, cwd or instruction overrides. Idle input uses `turn/start`; busy input
uses `turn/steer` with the selected `expectedTurnId`. Pending approvals remain
with the original user/session. Metadata-only preflight waits before beginning
an input attempt. Interleaved events are deadline-bounded, and resolved approval
IDs are removed without retaining their tool/command payloads.

The AGY adapter selects `agentapi_path` and `conversation_id` for the existing
application. It queues a bounded native-inbox reference to that exact
conversation; the Agent uses its configured Peerwork inbox tool to read the
verified item, without a spool-file read or additional file permission.
Decrypted bodies and business structure never enter the `agentapi` command-line
arguments, which may be visible to local process inspection.
The encrypted dispatcher/bridge ledger retains original input and outcome
evidence. Command-line bounds are checked before starting `agentapi`, including
a12,000 UTF-16-unit prompt limit. Oversized input is a no-input preflight refusal,
never a silent file-based fallback. A formerly configured `inbox_directory` may
remain as frozen candidate binding metadata but is not opened or written; new
configurations omit it. Do not edit an existing bridge's pinned host fields or
discard its old uncertain ledger merely to remove that metadata.
It does not launch a headless
model or add permission-bypass flags. A successful sidecar queue result is
`HOST_QUEUED`, with execution/model processing unproven. Actual sidecar/app
qualification is still pending. A cross-user bridge must return an exact
`peerwork.host-result.v1` envelope binding the original call, selected destination
and frozen frame hash. Old generic bridge success/errors do not qualify it.
The native bridge server is implemented below. Linux root/nobody qualification
uses a synthetic existing session and private Unix socket; actual Agent
application/model acceptance remains pending.

Verified inbox events wake the dispatcher directly. A 500ms fallback checks
scheduled retries; subscriptions do not run additional SSE/lease owners.
Messages in a native conversation, or business events in one instance, retain
order within the mailbox. Only eligible lane heads are scheduled: an unknown
call blocks its lane, while independent lanes can continue. Head selection uses
bounded indexed seeks rather than walking blocked siblings or retained success
history. Bodies use an explicitly partial UTF-8 preview up to 8KiB; external peer
data is labeled as untrusted notification data, not authority or permission.

Before any input call, the inbox persists its immutable call ID, source digest,
receiver/generation, membership, actual destination, frame hash and encrypted
frozen frame. Interrupted calls reopen as `RESULT_UNKNOWN`. A timeout, later
local error, new session, duplicate event or restart never establishes
`NOT_SENT`. Only scoped evidence may resolve the original call.

For an adapter with original-receipt lookup (currently the strict bridge
contract), the dispatcher automatically observes pending unknown/queued calls.
A scope-indexed durable schedule reserves the next probe before IO. Four bounded
range seeks cover the two unresolved states and backwards-clock repair; no
retained successful-call scan is required. At most one receipt probe runs per
scheduling round, rotating subscriptions so an unavailable scope cannot consume
all host work. Observations never invoke `deliver`, rerender or mint a call ID.
A matching queued/accepted receipt or bound no-send result merges into that
original call through the same private evidence path. Generic errors, unknown
results and mismatched call/frame/session evidence leave its facts unchanged.

The receipt envelope must be `peerwork.host-result.v1` and match the complete
frozen binding, selected destination and frame SHA256. A queued call can later
acquire an accepted fact without losing its queue fact. Recipient restart
preserves both the original call and probe backoff. Direct Codex/AGY adapters
currently provide no exact original-call lookup: their unknown inputs remain
blocked, without history scans, manual state toggles or automatic resends. The
native bridge stores actual underlying adapter results independently of the
signer connection. It cannot invent a receipt when the underlying host itself
lost its ACK: that original remains unknown. Earlier strict-contract tests use a
synthetic bridge-protocol peer; native-server tests exercise the actual local
HTTP implementation with a synthetic existing-session host.

Queue and host-acceptance receipts remain independent retained facts; neither proves
application consumption or model response. Shutdown awaits the active host call
and its evidence save before closing the owning engine. Fatal dispatcher exits
pause their subscriptions without deleting custody evidence or peer messages.

`delivery_status(options, item)` and the corresponding JSONL method select
local receiver-attested host evidence for one delivery, with
`model_response: NOT_ATTESTED`. Reporting separately identifies `LOCAL_ONLY`,
`PENDING`, `SERVICE_CONFIRMED` or `BLOCKED`, plus a selected reporting error.
It never invokes or retries host input.

The engine uploads cumulative call facts through signed
`structure.mailbox.report` controls. `structure.message.receipts.read` returns
the latest call per target in one sender request; the core independently checks
the recipient's signature, exact report/delivery binding and facts. This separate
control verifier cannot qualify a report as immutable business author evidence.
Reports bind the current upload authority to the original call/destination,
without uploading plaintext or a rendered frame. A current recovery owner may
upload retained older-epoch facts under that same binding. Lost replies retry
only the facts. A stale confirmation never clears a newer dirty version, and a
permanently rejected report is retained and quarantined while healthy reports
continue. Receiver observation expiry is independent of retained host facts.

Safe takeover/rebind and real Agent hosts remain incomplete. Terminal-call
reclamation is implemented below. The
local host ledger is bounded to 32MiB reserved allocation and 65,536 calls, with
at most 32 attempts per delivery; capacity exhaustion must not discard uncertain
original evidence. Reports use the same bounded mailbox control workers as
leases and selective ACK, without waiting for remote storage ACK before eligible
local input.

## Native host-user bridge candidate

Bridge journal identity is independent of its current allowed grant set. Stop
the local bridge, edit the protected configuration and run
`peerwork bridge set-grants BRIDGE.json EXPECTED_REVISION`, then restart it.
`BRIDGE_READY` exposes the current `grant_revision`. A stale revision or a live
bridge refuses the update. Empty grants revoke all clients; prior credentials
then fail authorization. Regranting access restores the same original call
lookup, without reinjection. New principals receive separate scoped credentials
in the derived endpoint descriptor. Worker client RPC has no grant-update API.

Owner-v3 stores a stable journal pin separately from versioned grants. Existing
owner-v2 metadata retains its exact old AEAD pin when upgraded after validating
the original journal. No historical call/key rewriting or bulk replay occurs.
Missing owner/keys/journal fail closed; unsupported older formats remain retained.
This operation changes grants only: physical host/session changes still require
an explicit separate recovery path. Revocation does not erase retained uncertain
calls or prove model consumption.

`peerwork bridge run BRIDGE.json` runs the bridge under the OS user who owns the
selected host session. This candidate adds no Node/Python runtime requirement.
Only the existing Codex and AGY App adapters are accepted; nested bridges,
managed/headless launch and permission-response options are rejected.

```json
{
  "format": "peerwork.host-bridge.v1",
  "state_directory": "/private/host/bridge",
  "host": {
    "kind": "codex",
    "endpoint": "unix:///private/host/app-server-control.sock",
    "thread_id": "EXISTING_THREAD",
    "expected_session_id": "EXISTING_SESSION"
  },
  "bindings": [{
    "expected_origin": "https://api.peerwork.dev/",
    "expected_actor": "RECIPIENT_ACTOR_ID",
    "expected_key_id": "RECIPIENT_SIGNING_KEY_ID",
    "namespace": "program:worker",
    "workspace_id": "WORKSPACE_ID",
    "mailbox_id": "MAILBOX_ID",
    "membership_id": "MEMBERSHIP_ID"
  }]
}
```

Replace the placeholders with exact selected identifiers. The private state
directory's parent must already exist with the current user's private
permissions. A resident client named `worker` uses namespace `program:worker`;
a root embedded client uses `program`, with further restrictions appending their
explicit names. Origins are canonicalized consistently with the participant
engine. Up to 32 exact identity/key/namespace/workspace/mailbox/member grants are
allowed; they do not grant any additional backend permission.

Startup emits `BRIDGE_READY` and a private endpoint-file path. A single
principal exposes `adapter` for `RuntimeConfig.hosts`. Multiple principals expose
`adapters`, each with its exact `principal` and narrow `adapter`; the ambiguous
single `adapter` is null. Select the matching identity/key/Origin/namespace.
Spaces of one principal share a credential; different principals do not. It records the actual selected session, immutable
configuration and grants. Another host/session or grant set cannot silently
reuse this state. Readiness here proves only bridge startup, not the recipient's
service stream, body keys, model processing or end-to-end Agent response.

The service binds only `127.0.0.1` and supports three authenticated POST methods:
`health`, `deliver` and `receipt`. Browser Origin requests, plaintext Bearer
transport and permission-response methods are refused. Each principal has an
independent capability key. AES-GCM authenticates/encrypts both directions;
responses bind the fresh request and method. The capability is never transmitted.
A process occupying an old local port can neither open a frame nor manufacture
a valid receipt. The private host master key is never exported to signers. Requests use strict JSON, bounded headers/body/time,
16 active HTTP connections and an eight-job queue. One owned worker serializes
host IO and local SQLite; no database transaction spans host IO. Standard Rust
HTTP handling shares the existing network stack; it adds no system runtime.

Every call binds the complete original scope, source/frame digests and exact
recipient destination, including a persistent `bridge_id`. Startup checks each
subscription's identity/mailbox access before allowing an input attempt. The rendered frame must retain its untrusted-data label
and match its incoming delivery/identity fields. Before host input the bridge
commits an encrypted frozen frame and scope proof. It then saves the underlying
adapter's result even if the signer's socket disappeared. A duplicate original
call reads that result; changed input cannot replace it. A host-side lost ACK or
interrupted call remains unknown, including after restart.

For an absent original that is neither retired nor in conflict with a retained
original source, `receipt` first commits a NOT_SENT tombstone binding the
call/message/frame. Any later arrival of that exact old call returns the
no-send result without input IO. The signer may only create a new attempt after
reconciling this bound result. Absence without a durable fence is insufficient.
Local admission reserves a 32 MiB / 4,096-call budget;
capacity exhaustion refuses admission and never purges uncertainty. Terminal
metadata can be retired under the exact confirmed-fact contract below.

A durable source guard covers Origin/Actor, workspace, mailbox, membership,
sequence and physical destination independently of receiver epoch or local
namespace. A fresh receiver cannot submit another call for an existing active
source. `HOST_ORIGINAL_INPUT_REQUIRES_RECOVERY` preserves uncertainty and cannot
be converted into a negative receipt for the replacement call. This is a safety
gate; importing/recovering the original ledger for a new owner remains pending.

The bridge retains its instance, local port, narrow credentials and encrypted
journal across restart. Missing owned journal/key/instance state fails closed.
A new empty bridge gets a different instance and cannot certify old calls as
NOT_SENT, even when its underlying Agent session is the same. Health may reconnect the same pinned existing session; a changed
session is refused. Approval waiting pauses LIVE bridge input before a signer
call attempt; AGY's explicitly queued-only capability stays distinct. Graceful
shutdown stops queued work and waits for the active call's evidence save.
The bridge frame-encryption key is a private local storage key, not a Peerwork
signing identity or workspace body key. Preserve it together with the bridge journal.

The private journal uses owner format `peerwork.bridge-owner.v2` with
`INITIALIZING`/`ACTIVE` phases. The master credential persists before initializer
metadata; schema creation commits atomically. An interrupted empty initializer
resumes with the same instance/credential. An active owner cannot recreate
missing journal, replay-frontier tables or credentials. Earlier unreleased
candidate owner files return `BRIDGE_JOURNAL_UPGRADE_REQUIRED` and are retained;
this is not automatic migration of the old candidate's state.

### Bounded completed-call retirement

Explicit application consumption and its verified service ACK establish a
mailbox retirement frontier. Host acceptance alone does not consume a message.
The engine selects at most32 service-confirmed terminal calls per batch, keeping
the exact original scope, frame/outcome digest and report version. Calls whose
reports are pending/quarantined, unknown calls and queued calls remain retained.
A future late acceptance still merges and uploads before it can be selected.

A scoped encrypted bridge `retire` control first records a durable source
frontier and deletes only explicitly listed matching HOST_ACCEPTED or NOT_SENT
records. Its ACK echoes the exact scope/frontier/call set; it is not a host-result
assertion. Only after verifying it does the inbox transaction retire the same
versions/facts and release their reserved allocation. Lost replies/restarts retry
idempotently. Each batch deletes at most32 calls; lane cleanup has a separate
persisted keyset cursor over at most32 projections. One tracked cleanup worker
per dispatcher has a two-second bridge budget, clones only the shared control
client and is awaited on all shutdown paths. Input/heartbeat work does not wait
for GC or another service storage ACK.

An absent original at/below the source frontier returns
`HOST_EVIDENCE_RETIRED`; deliver and receipt cannot turn it into NOT_SENT. The
frontier survives receiver/namespace changes and full bridge/runtime restart.
`delivery_status` identifies retired local evidence as `LOCAL_EVIDENCE_RETIRED`;
sender-visible signed service reports remain available. SQLite allocation/pages
become reusable; this does not promise physical database shrink per message.
Consuming before input begins cancels unstarted work, while CALL_OPEN/unknown
ordering guards remain. Ordinary item/lane projections already use a foreign-key
cascade; no redundant historical sweep is added for them.

Seventy-record units qualify bounded pages, replay barriers, retained
unknown/queued facts and late acceptance. The genuine HTTP/E2EE/native-host case
qualifies application consumption, retirement, both-side restart and replay
refusal without a second host input. Providers remain synthetic; actual
Agent/model and IM-percentile qualification is still pending.

For different OS users, an authorized installer must provision a separate
private copy of the selected principal's narrow credential for the signer and
select that copy in `adapter.token_file`. Never distribute `bridge-token` (the
host master) or `bridge-key` (local frame encryption). Keep original host sockets and identity-key
permissions intact. A Linux root/nobody test qualifies this boundary: the signer
cannot connect to the root-owned private Unix socket or read the master token,
but can use its granted credential to deliver and query the exact original
receipt. A wrong scope is refused and duplicate original calls produce one
synthetic host input. Staging credentials, socket and executable are removed.
This is actual cross-UID access qualification with a synthetic provider, not a
real Agent application/model test or automatic provisioning feature.

Direct adapters and the host-user bridge now hold OS-user-scoped session locks
outside individual runtime state directories. The selected endpoint/conversation
is locked before connection; the verified host/session/conversation is locked
before any peer input. An endpoint alias cannot bypass the second lock. Distinct
sessions remain independent, and many granted bridge clients share the bridge's
one physical worker. Locks remain held through reconnect and release on process
exit without deleting lock files. They coordinate independent state roots in
the same OS user/IPC namespace, not remote machines or mutually untrusted
processes running as the same user. Different users should use the designated
host-user bridge rather than separately opening the physical host.

Lock release does not prove an old input was processed or not sent. Automatic
state transfer, safe takeover/rebind, automatic credential provisioning and
actual Agent/app acceptance remain incomplete. Preserve the original protected
runtime/bridge state; a new empty directory is not an uncertainty recovery path.
The general participant JSONL IPC shares the authenticated/encrypted local
primitive described below. The actual native HTTP bridge server and genuine
E2EE participant path are separately exercised.

## Current reachability and automatic body keys

Host observation age includes local scheduling and probe IO time. A slow probe
keeps its original monotonic start; delivering its callback does not refresh the
observation. Future observation timestamps are rejected.


Current observations are separate from retained host-call facts. The native
receiver advertises its signed-SSE link only after verifying an initial frame,
including an empty mailbox. Existing-session metadata health is observed every
three seconds. A heartbeat carries observation age, so renewing a lease cannot
turn an old successful probe into a current one. The service expires host
observations after ten seconds and key observations after fifteen seconds.
A queued-only AGY endpoint remains `QUEUE_ONLY`; a queue receipt is not live
model readiness. Approval waiting is visible without bypassing permissions.

`structure.mailboxes.read` and `structure.mailbox.get` expose current downlink,
host mode/execution/freshness, body-key state/commitment, capacity, ordering and
`PATH_QUALIFIED` versus `UNCONFIRMED`/`QUEUE_ONLY`. These are receiver attestations,
not host signatures, model replies or a delivery-time SLA. A retained unknown
call prevents claiming an unobstructed path while independent ordered lanes can
still progress. Application/business acceptance remains separate. Scope and
lease checks apply on every current disclosure. The service compares the
reported key commitment/epoch with its current usable head; a rotation therefore
invalidates the old READY claim before the receiver's next heartbeat.

A counted receive-only key-preparation lane follows verified mailbox claims and
leases. It reads only that authorized mailbox's Owner-signed head and at most
32 explicitly selected key IDs, reuses native recipient-bound signature/HPKE
verification and imports only existing Owner-authorized deliveries. It never
publishes a missing head, rotates keys, grants access or replays workspace
history. One job is shared across same-workspace scopes, independent of heartbeat
permits and foreground operations. A missing historical message key requests
only that selected verified delivery's key, within the same bound.

READY/NOT_REQUIRED observations refresh every ten seconds; missing/error cases
retry after two seconds, with a ten-second job budget. Imported keys wake up to
32 eligible key-blocked lane heads through an index. Permanent immutable-message
opening errors are not misclassified as a request to fetch more keys. Local
snapshots include explicit freshness and key error codes. A missing key keeps
the path unconfirmed; it does not require the receiving Agent to implement an
import loop or repeatedly run `keys.accept`.

Historical prerequisites are indexed durably when a verified encrypted message
and its cursors commit. Each job selects at most 31 distinct missing historical
keys plus the current key; a persistent keyset cursor advances before network IO,
so interrupted jobs and permanently unavailable keys cannot monopolize a prefix.
The queue stores a tiny sealed reference to the original delivery/frame/member,
not body plaintext or key material. Selecting keys does not reopen every large
frame or scan message history. Existing retained keys are checked locally.

A result updates only its selected keys. Ready keys wake corresponding lane heads
through independent indexed pages of at most 32 references, even while other
keys remain unavailable. Rechecking the current key does not restart a long wake
traversal. Any outstanding missing prerequisite keeps aggregate key readiness
MISSING. Consumption, terminal state, native message withdrawal and physical
inbox retirement remove their unused references without removing key secrets or
original evidence. Queue rows share the inbox's existing item/byte admission
bounds. Synthetic local tests exercise 70 distinct keys across restart and 70
shared-key wakeups; this is recovery evidence, not IM latency qualification.

Opening a local inbox checks its identity/Origin binding before recovering old
host calls. A different principal cannot turn another runtime's open call into
an unknown result or alter its report version.

For an already-active member, an Owner who needs to supply keys without replacing
its membership generation uses `participant.access.approve` with
`mode: "KEYS_ONLY"` and a fresh recipient request. `SESSION` creates a new member
generation and invalidates old-generation addresses. The HTTP qualification
preserves the listener/member/mailbox through a missing-key to KEYS_ONLY delivery
recovery, then opens genuine encrypted mail automatically. It also checks an
empty signed-frame self-test, approval wait/resume and that receiving creates no
probe messages or key epochs. Actual Agent-host application qualification is
still pending; these cases use a synthetic existing-session protocol fixture.

## Resident runtime and authority

An administrator supplies a protected `RuntimeConfig` with format
`peerwork.participant-runtime.v1`, a private `state_directory`, named `engines`
and named `clients`. Every client names exactly one engine and explicit
`Capability`. Engine configuration contains the identity/state paths; individual
requests cannot supply those paths, another profile or another actor.

The runtime writes separate protected endpoint files:

- `client-NAME.json`: one client token, bound to its preconfigured capability.
- `admin.json`: a distinct token for runtime status and stop.

Client requests cannot shut down the runtime. Instance-restricted clients cannot
turn workspace-wide operations into instance operations by adding header fields.
`Capability.mailbox_ids` separately narrows communication references, including
recipients, reply addresses and every nested workspace/mailbox in stream scopes.
Business-limited clients must explicitly select their communication mailbox
boundary. SOURCE/subscription instance selectors are checked separately. A
mailbox-limited capability cannot call broader discovery/message-by-ID methods
by adding an ignored mailbox field; these require a broader program/admin view.
Indirect instance selectors must match the pinned instance; they cannot switch
to an unrelated package. Scope verification also checks returned protocol pins.
Tokens isolate requests, not mutually hostile programs with unrestricted access
to the same OS user's credential files. Cross-user host access still needs an
explicitly scoped bridge; do not relax a host control socket's permissions.

Source CLI entry points are:

```text
peerwork runtime run PRIVATE_CONFIG.json
peerwork runtime call CLIENT_ENDPOINT.json PRIVATE_REQUEST.json
peerwork runtime admin ADMIN_ENDPOINT.json status
peerwork runtime admin ADMIN_ENDPOINT.json stop
```

The listener is loopback-only. Endpoint files contain `format`, `address`,
`token` and `access`; they must not be published. The token is never sent over
the socket. Use native `communication_runtime::call` or the CLI for foreign
language integration rather than implementing signing, encryption or recovery.

Before sending private data, the client sends a `peerwork.participant-hello.v1`
frame containing only the opaque capability key ID and a fresh client nonce.
The runtime returns an encrypted `peerwork.participant-challenge.v1` proof bound
to the exact hello bytes (including the JSONL newline), with that client nonce
and a new server nonce. The client verifies the peer, then sends a bounded
`peerwork.participant-auth.v1` encrypted confirmation proving its own key.
Unanswered proofs expire after two seconds; knowing a key ID does not reserve a
long-lived authenticated slot. A legitimate client allows four seconds for its
challenge while unauthenticated slots expire.

Business request/response JSON is encrypted/authenticated with the shared local
AES-GCM primitive. Directions and methods are separated. The method includes the
fresh connection nonce; replies bind their original encrypted request. Another
connection's packet, a forged peer challenge or a completed request replay is
refused before any new handler admission. Admin and client keys stay distinct.

The decrypted request has format `peerwork.participant-request.v1`, a unique
`request_id` and `request`, with no token or profile selector. It travels inside
`peerwork.participant-sealed-request.v1` with a `payload` ciphertext string.
Decrypted responses use `peerwork.participant-response.v1`, correlate the request
ID and contain either `ok: true, value` or `ok: false, error`. The wire wrapper is
`peerwork.participant-sealed-response.v1` with `request_id` and `payload`.
This protects local transport; native service/author evidence is still verified
inside the participant engine. Client methods are `capabilities`, `invoke`, `request`, `operation`, `recover`,
`operation_result`, `operations`, `watch`, `watch_next`, `inbox`, `consume`,
`delivery_status` and `unwatch`;
`ClientRequest` is the canonical schema. `watch_next` accepts an explicit wait
budget up to 30 seconds and may return `WAIT_EXPIRED`; durable reception continues.
It waits for local notifications and does not poll the remote service. Only one
pending wait per client/watch is admitted. Other calls remain multiplexed while
that wait is pending. The admin method is
`status` or `stop`. Extra fields and duplicate JSON keys are rejected.

Connections can carry multiple requests and responses may arrive out of order.
Use request IDs for correlation; operation IDs identify durable mutations.
Ingress permits at most 16 connections and 4 outstanding calls per connection.
Each connection retains at most 256 request IDs, including completed calls;
open a new authenticated connection afterward. The connection observation lifetime
is at most five minutes. Plaintext payload limits stay 512 KiB for requests and
approximately 32 MiB for replies; separate wire limits cover ciphertext expansion.
The bridge's smaller payload bounds do not truncate the program API.
Caller disconnect never detaches an uncounted mutation worker. New runtime
startup rotates endpoint tokens. `LOCAL_READY` means local ingress is available;
it must not be displayed as `CONNECTED` to an Agent.

## Asynchronous collaboration

Normal send waits for verified service acceptance, not another model's reply.
The short Agent Skill will teach early dispatch of independent work, useful work
while results are pending, explicit dependency waits and yielding when no ready
work remains. Program Masters use their event loops for the same behavior.
Transport does not invent task completion or keep Agents busy with duplicate work.

## Current qualification evidence

Linux synthetic tests cover offline encrypted admission, quota rejection,
identity/state ownership, authority narrowing, indirect selectors, committed
key-delivery state, real HTTP root lifecycle and warm single-request reads,
independent progress during a slow request, lost-response restart without duplicate
effects, caller disconnect, multi-frame IPC, separate admin authority, token
rotation, and verified-anchor expiry. Automatic watch qualification now additionally covers offline first receipt,
real program reply, selective asynchronous ACK, normal EOF/token-path reconnect,
lost claim-response recovery without another epoch, three mailboxes sharing one
verified stream, local IPC reception while a separate call progresses, explicit
pause/resume, trusted-clock jump repair, scope fencing isolation and explicit
persisted-recovery errors. These do not establish the proposed IM latency
percentiles, production availability or real Agent host delivery.

## Native Agent CLI and MCP projection

The candidate `peerwork agent` frontend attaches to an existing scoped client
endpoint. It never opens another signing engine, selects another identity,
creates a receiver from guessed values or launches a model. Native CLI, stdio
MCP and ordinary programs share the same owner, pool and durable operations.
No Node/Python runtime is needed by these frontends. Each MCP frontend process
is a thin transport endpoint, not an additional receiver/host dispatcher.

A protected `peerwork.agent-profile.v1` JSON file contains:

```json
{
  "format": "peerwork.agent-profile.v1",
  "endpoint_path": "/owned/runtime/client-worker.json",
  "expected_origin": "https://api.peerwork.dev",
  "expected_actor": "ACTOR_ID",
  "scopes": {
    "project": {
      "workspace_id": "WORKSPACE_ID",
      "mailbox_id": "OWN_MAILBOX_ID",
      "membership_id": "OWN_MEMBERSHIP_ID"
    }
  },
  "contacts": {
    "master": {
      "scope": "project",
      "recipient": {
        "mailbox_id": "MASTER_MAILBOX_ID",
        "membership_id": "MASTER_MEMBERSHIP_ID"
      }
    }
  },
  "protocols": {
    "tasks": {
      "workspace_id": "WORKSPACE_ID",
      "instance_id": "INSTANCE_ID",
      "protocol_digest": "PROTOCOL_DIGEST"
    }
  }
}
```

Replace placeholders with exact enrolled IDs and the full lowercase protocol
SHA256. The profile and endpoint use the native protected-file checks; keep
POSIX mode0600 in an owned private directory, or the qualified Windows ACL.
The profile does not confer service permissions. The daemon independently
restricts this endpoint's actor, operation catalog and scope. Mail scope lookup
selects an already enabled resident binding, including its original consumer
and destination; it does not guess or replace a host binding. At most eight
active bindings are returned and other client namespaces are excluded.
Contact aliases pin exact mailbox/membership generations, not arbitrary actor
labels. The service atomically validates the selected recipient and return
address. Rejoining requires explicit updated contact/profile selection.

`communication_runtime::RuntimeClient` verifies actor and Origin before private
work, forbids admin endpoints, and rechecks if restart replaces the protected
endpoint. Verification and the following call use the same descriptor snapshot.
Local RPC exchanges currently open individual authenticated encrypted connections;
the resident engine retains the remote HTTP pool and SSE stream.

```sh
peerwork agent --help
peerwork agent --profile /owned/agent.json context
printf '%s' 'Please investigate the build failure.' |
  peerwork agent --profile /owned/agent.json send master --id investigate-build-1
peerwork agent --profile /owned/agent.json inbox project
printf '%s' 'Investigation complete; see the attached protocol action.' |
  peerwork agent --profile /owned/agent.json reply project SEQUENCE/DELIVERY_ID --id report-build-1
peerwork agent --profile /owned/agent.json status report-build-1
peerwork agent --profile /owned/agent.json call consume '{"scope":"project","items":[{"sequence":1,"delivery_id":"DELIVERY_ID"}]}'
```

`--text-file FILE` is the alternative to stdin for send/reply. Use stable IDs;
unknown results use `recover ORIGINAL_ID`, never a replacement send. Replies
select exactly one pending local delivery and derive conversation/return address
from verified author-signature and AEAD output. Reply does not automatically
consume input. Inbox output omits wire proofs/ciphertext and labels peer content
as external data. Status reads the original local operation; explicit receipts
perform one selected native message query, without route enumeration.

For stdio MCP, configure the host to run the native executable with arguments:

```json
["agent", "--profile", "/owned/agent.json", "mcp"]
```

The entry exposes `peerwork_context`, `send`, `reply`, `inbox`, `consume`,
`status`, `recover`, `receipts`, `wait`, `protocol`, `read` and `act` (each with the
`peerwork_` prefix). `peerwork agent tools` prints the exact shared schemas.
`read` selects an instance's current state/revision, an exact record revision
or at most32 current records with a native continuation cursor. Verified opened
contents are retained; wire proofs and sealed bodies are omitted from the tool
projection. `act` requires `expected_revision` from the relevant instance read
or event; it never guesses the concurrency guard or silently refreshes/retries
changed business input. It maps data to `structure.action` for a configured
protocol, not a second handwritten business-action implementation. Runtime/service grants
remain authoritative. Administration, profile switching and arbitrary paths
are absent from tool arguments.

MCP supports negotiated `2025-11-25` initialization and `2026-07-28` per-request
metadata/discovery. Tools can be discovered while the runtime is offline;
execution returns an explicit error rather than creating a new engine. Up to
16 tool observations run concurrently; an inbox wait cannot serialize an
unrelated send. Frame and output sizes are bounded. Cancelling/closing MCP
ends its observation and emits no later result for that cancelled request;
an already admitted durable operation continues in the resident runtime with
its original ID. Reopening MCP does not replay a mutation automatically.
`wait` uses local mailbox notifications with an explicit sequence and budget;
initial state/heartbeat notifications alone cannot satisfy an arrival.

The portable [Peerwork Skill](../skills/peerwork/SKILL.md) supplies short tool,
recovery and asynchronous-work guidance. Installing it or changing a user's
Codex/AGY environment is not automatic. Actual host installation/first-use,
IM percentiles, uncertain-ledger handoff and the three announced platforms
still require qualification before release.

MCP references: [per-request versioning](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning),
[stdio](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/stdio)
and [negotiated initialization](https://modelcontextprotocol.io/specification/2025-11-25/basic/lifecycle).

## Explicit same-host engine handoff

The native candidate can move one **existing native** engine's encrypted local
indexes to another protected directory on the same host:

```sh
# Stop the owning runtime or embedding program first.
peerwork runtime transfer-engine /owned/runtime.json worker /owned/worker-state-next
# Start the generated configuration after TRANSFER_READY.
peerwork runtime run /owned/worker-state-next/transferred-runtime.json
```

This is an explicit local maintenance operation, not part of changing a business
protocol. It keeps the selected actor/Origin, authority, client names and grants,
Runtime directory, host/session pins, mailbox/receiver identities, claim packets,
cursors, encrypted host frames, uncertain/queued/accepted facts and report state.
It does not change the selected host or reinterpret an old task report as mail.
It is absent from Worker MCP tools and client RPC requests.

Identity, original native journal and body-key paths stay at their original
locations. The generated configuration pins the original journal explicitly even
when it was formerly selected by a default. **Retain those original paths**;
the output's new state directory does not make the old directory disposable.
No seed or body key is exported, copied or regenerated by this operation.

The source engine, shared journal, Runtime and target ownership locks exclude
live writers. The source principal binding and both index bindings are checked
before transfer. A target must be empty or belong to this exact interrupted
job; other identities, destinations, configuration digests and existing data
are refused. SQLite's snapshot API copies the operation/inbox databases in
bounded page batches, preserving the encrypted original records rather than
rebuilding semantic state. Physical consistency is checked once during transfer;
normal startup reads only the small transfer markers, without hashing/scanning
retained history.

A protected target reservation prevents partial state from starting. The source
is then durably fenced before copying, and remains fenced if transfer is
interrupted. Rerun **the same command/configuration/target** to finish that job;
do not remove its markers or create another receiver. Only a fully copied target
is marked READY. A retry after READY observes that original job and never copies
over a target that may have accepted new operations. This runtime refuses to reopen
fenced source state. This is a cooperative native-runtime fence,
not a security boundary against code that bypasses its ownership protocol.

`TRANSFER_READY` proves local handoff, not service or Agent connectivity. The
candidate tests terminate the transfer process at multiple durable boundaries,
resume the same job, and preserve new target writes after a READY interruption.
The HTTP host fixture also transfers existing RESULT_UNKNOWN/HOST_ACCEPTED calls,
continues reading fresh E2EE mail with the original key paths, and retains the
original host input count instead of reinjecting those old calls.

Cross-host/key relocation, converting the published Node receiver/bridge format,
upgrading unsupported pre-v2 bridge journals and changing physical host/session
bindings are separate pending work. The native owner-v2 to owner-v3 metadata
upgrade described above preserves its original journal pin. Unsupported legacy files are retained; this
command does not claim to import those formats or resolve old uncertainties.


## Candidate qualification tools

The maintainer-only ignored tests in `participant_live_host_tests.rs` separate
real host use from SDK/service measurements. They are not runtime dependencies
or an automatic user-harness installer. They use an explicit local synthetic
PostgreSQL/HTTP fixture and generated identities, never a production profile.

`program_master_existing_session_and_native_agent_reply` additionally requires
an explicitly selected protected `PEERWORK_LIVE_HOST_CONFIG`, an unused absolute
`PEERWORK_LIVE_HOST_STATE_DIR`, a unique `PEERWORK_LIVE_HOST_NONCE`, and
`PEERWORK_LIVE_HOST_REPORT` **inside that state directory**. The configuration
uses the existing Codex/AGY adapter schema; no model process/thread is created.
The test sends one E2EE Ping through the native tool surface. The actual existing
Agent must reply using its protected generated Worker profile and the native
`reply` tool. A matching sender-signed, decrypted PONG with the original
`reply_to` is required; a host ACK alone cannot pass. A reused state root/result
is refused. Preserve failed-run state and reconcile its original outcome before
attempting another input. Completed test state may be removed after the owned
runtime/bridge are terminal and the verified result has been retained.

The report distinguishes service acceptance, receiver-store observation, host
fact and actual reply. Its observation times share one monotonic clock and
include observer scheduling; they are not isolated internal phase spans.
A real existing Codex round trip passed on2026-10-30 with one HTTP send per
message and zero journal reads. That single unoptimized local-service sample
observed acceptance in716ms, receiver storage in976ms and PONG in46.3s, including
model/tool scheduling and a rejected relative-profile-path attempt. It does not
qualify IM percentiles, fresh-Agent first use, a production WAN path or AGY.

The profile-file loading issue from that use is corrected: CLI profile paths
may be absolute or relative to the process working directory. The selected
file/parent still must satisfy native ownership, permission and symlink checks;
profile endpoint/identity bindings remain explicit absolute configuration.

`two_program_warm_mail_latency_and_request_counts` uses
`PEERWORK_PROGRAM_LATENCY_REPORT` in a protected report directory. It separates
one first send from32 subsequent samples and requires every accepted sample to
arrive and decrypt. Reports retain every sample, actual send/discovery/context
counts, build mode and the observation basis. There is no host/model input.
Unoptimized or local two-program results cannot qualify the full1–8-participant
release gate. Run the same selected test against an optimized build before
attributing debug-build cryptographic cost to the architecture.

The optimized local two-program run on2026-10-30 observed warm acceptance
p95 of181.65ms and receiver-store observation p95 of308.50ms over32 samples.
All33 messages arrived and decrypted, with33 send requests and no discovery,
context or journal requests during the measured interval. This is a local
two-program baseline, not WAN, model-response or1–8-participant qualification.

`tests/qualify-agy-native-mcp.py` is a maintainer-only controller for
`fresh_agy_native_mcp_reply`. It starts one explicitly authorized fresh AGY CLI
project/process with workspace-local MCP and the short Skill, using existing
AGY authentication. It temporarily grants only its uniquely named test server's
seven selected tools and removes those grants afterward. It does not install a
global MCP server or use a permission bypass. Supply the explicit SDK, test
binary, native CLI, AGY, Node fixture, product, PostgreSQL and fresh output paths
shown by its `--help`; Python and Node are test dependencies, not client runtime
dependencies. This controller changes the invoking user's AGY settings briefly;
run it only where that scoped test configuration is authorized.

One fresh AGY process completed two E2EE Ping/PONG rounds using only
`peerwork_context`, `peerwork_inbox`, `peerwork_reply`, `peerwork_consume` and
`peerwork_wait`. Each reply was sender-verified by the program participant;
the fixture observed four send requests and zero journal reads. Reply
observations were45.4s and30.1s in an unoptimized local-service test. This
qualifies first use through MCP wait, **not AGY App host push**, busy-session
delivery, IM latency or a percentile. The controller's external process/tool
evidence is required alongside the native fixture result.

Agent inbox items now include ready-to-copy `reply.arguments` and
`consume.arguments`. Copy these references and add the required reply operation
ID and text; routing comes from the authenticated original inbox item. Raw
reply addresses are omitted from the Agent projection. Invalid MCP arguments
return the required shape plus `NOT_SUBMITTED` and
`CORRECT_ARGUMENTS_KEEP_OPERATION_ID`, so an Agent can fix its call without
inventing routing metadata or assuming a remote effect.

`one_to_eight_program_concurrent_mail_latency` uses a fresh protected
`PEERWORK_PROGRAM_MATRIX_REPORT` and measures concurrent ring sends among1,2,4
and8 independent identities in one workspace per case. Every first round is
reported separately from32 warm rounds; every accepted message must arrive and
decrypt, and no failed sample is discarded. This is small-message local traffic,
not the full8KiB/WAN/host gate. The optimized quiet2026-10-30 run observed warm
acceptance p95 of179.85/272.28/398.82/681.38ms respectively. All495 messages used
exactly495 send requests and zero journal reads;4 and8 participants **miss** the
300ms target. A preceding run overlapping compilation and another Agent test
failed the request-count check (268 requests for264 messages in its8-participant
case); retain that evidence rather than replacing it with the quiet result.
The cause of those four extra requests was not captured by that earlier run.

For explicit maintainer diagnostics, `PEERWORK_PARTICIPANT_HTTP_TIMINGS` names a
new protected output file. The synthetic Node fixture buffers bounded action,
status, error-code and monotonic duration metadata and writes it once on shutdown,
without packets, identities, keys or body text. Its duration ends at response
headers and is not the client acceptance span; never subtract their quantiles.
The quiet run recorded zero HTTP/service errors and send-handler p95 of85.72ms.
Further native queue/preparation/persistence attribution remains required.

The AGY qualification controller now records monotonic step observations and
harness-reported tool/agent-response durations without response deltas or
reasoning text. One instrumented default-effort trial spent96.1s in reported
agent-response steps and16.7s in seven tool steps over125.3s overall. An explicit
test-session `--effort low` comparison still observed42.8s/25.7s replies; no
global/model configuration was changed. Neither two-sample result is a latency
guarantee or a substitute for host delivery measurement.

The native engine now exposes twelve fixed `http.local_phases` counters through
`metrics()`: session open, body preparation, packet preparation, saved-packet
loading, HTTP roundtrip, response verification/store, admission reservation,
running-state store, completion store, body-key selection, sealing/signing and
body-packet persistence. Each reports count, cumulative
microseconds and lifetime maximum, using a monotonic clock and completed scope
exits including errors/cancellation. Concurrent/nested spans can overlap;
snapshots are observations, not a new signed clock or transaction. Never
subtract their maxima or treat an aggregate average as a percentile. No body,
key, operation ID or arbitrary caller-supplied label is recorded.

The matrix report keeps before/after counter snapshots per anonymous participant
index. `PEERWORK_PROGRAM_MATRIX_CASES` and `PEERWORK_PROGRAM_MATRIX_ROUNDS` permit
explicit shortened diagnostic runs; the defaults remain1/2/4/8 and33 rounds.
Shortened/debug runs do not qualify the release gate.

Maintainers may select an exact encrypted plaintext size with
`PEERWORK_PROGRAM_MATRIX_PAYLOAD_BYTES=8192` (128–8192 bytes; unset preserves
the earlier small-message samples). `PEERWORK_FIXTURE_LINK_RTT_MS=100` applies
50ms to each request direction and to each response/SSE direction in the
synthetic fixture. Burst chunks overlap their delays instead of paying a new
50ms serial penalty for each chunk; the bounded queue fails explicitly if
exceeded. Test-control endpoints bypass the simulated link and are excluded
from acceptance timing. This exercises fixed link latency, not TCP/TLS setup,
bandwidth limits, jitter, packet loss or an actual WAN deployment.

New matrix receive observers run concurrently with each participant's outgoing
send, so an incoming message need not wait for that participant's outgoing
acceptance. The reported receive time is still a post-store observer timestamp,
not an isolated service-acceptance-to-store span. Retain the timing-basis field
when comparing earlier reports that observed receive after the outgoing send.

The candidate removes a throwaway signature before applying verified service
time and authenticates durable HTTP responses once inside the journal before
recording them. Final packet validation, cached-result business-input equality,
original packet recovery and response authenticity remain mandatory.
Fresh encrypted payloads acquire verified service time before electing their
durable packet, avoiding an immediately expired placeholder attempt and its
unnecessary authorization archive. A producer that just saved its own typed
packet does not decrypt/re-sign that same winner; conflicting/concurrent and
resumed producers still verify, decrypt and compare the original saved bytes.
Older pending attempts retain their original renewal/recovery path and history.
Local key-store opening and lifecycle Origin normalization now use the same
pure URL validator as real HTTP construction, without building a TLS client,
loading network trust roots or creating a discarded pool. Origin canonical bytes,
TLS/explicit-loopback scheme policy, private state and stored-Origin checks stay
the same. Network trust/proxy/certificate options are validated when constructing
the actual HTTP client; local key storage has no network authority to configure.
Application consumption can now acknowledge custody cumulatively: the SDK
persists the consume request, uploads its fenced ACK and only records remote
confirmation after verifying that response. Background custody ACKs get a
non-extending25ms coalescing window, while item/host notification remains
immediate. Unconsumed custody and consumption batches alternate under mixed
load and each indexed selection remains bounded to32. A local consume, queued
ACK or host acceptance still does not prove that a model read or replied.

The native admission/inbox indexes use single-owner WAL with FULL synchronous
commits on a local filesystem; identity, encryption, durable reservation and
recovery boundaries stay the same. Sidecars are checked before SQLite opens
them, and newly created sidecars retain private ownership/ACLs. Transfers use
the SQLite snapshot path; a live WAL is not disposable.

After these corrections, the full local optimized small-message matrix observed
acceptance p95 of95.56/121.19/214.71/237.34ms for1/2/4/8 independent program
identities. All495 messages arrived and decrypted, with exactly495 send requests
and zero discovery/context/journal requests in the measured intervals. These
41–42-byte payloads establish the initial local acceptance slice only; the
maximum-payload qualification below is separate. Receiver observation p95 at8
participants was305.23ms from call start;
that is not an isolated service-acceptance-to-store measurement.

The subsequent full 8KiB plaintext matrix found unnecessary heartbeat traffic:
local consumption was forcing a new pulse before its ACK. Consumption now wakes
the ACK scheduler without changing the lease/presence heartbeat deadline.
Periodic renewal, expiry checks and actual readiness changes are preserved.
After this correction, local warm acceptance p95 was91.87/113.29/161.35/297.36ms
for1/2/4/8 independent identities. With the explicit simulated100ms RTT, it was
243.84/228.21/249.20/372.06ms. Each full matrix delivered/decrypted495 messages
with exactly495 send requests and zero discovery/context/journal requests.
The8-participant delayed-link case **still misses** the300ms target; this is
not a complete IM release qualification. The full matrix records heartbeat
counts and rejects a heartbeat per consumed message. Retain the earlier
317.22ms local /500.70ms delayed-link8-participant misses as their own evidence.

`tests/installed-participant-smoke.py --cli /absolute/path/to/peerwork` exercises
a copied native executable with synthetic identity, private Unicode paths,
scoped encrypted local IPC, administrative denial, competing-owner refusal,
kill/restart and normal shutdown. Python is the maintainer's test driver, not
an installed client dependency. The current Linux candidate passed this check.

The dedicated `Native participant qualification` workflow prepares exactly
Linux x86_64 GNU/glibc2.28, macOS ARM64 and Windows x86_64 candidates. It builds
the CLI and affected native tests without Node/Python extension builds and
does not invoke the older experimental publisher. Temporary CI artifacts are
not signed/notarized public releases. The first CI run found a JSON version-output packaging error and a Windows
snapshot flush using a read-only handle; both are corrected in a subsequent
candidate run. The first macOS job never acquired a runner because of hosted
ARM64 capacity constraints. Corrected three-platform qualification remains
pending; do not infer a pass from local Linux tests. Audit the
emitted loader dependencies and final installation separately from language
runtime requirements.

Foreground sends also expose `http.send_execution_phases`. A Tokio task-local
scope counts only the native `structure.message.send` execution and its awaited
prerequisites; separate watch/ACK tasks do not inherit it. Admission, scheduling
and final operation-store work occur outside this execution scope. Failed and
cancelled scope exits still count. Nested body stages overlap `body_prepare`;
these are cumulative observations, not an additive percentile breakdown. Only
fixed names/counts/durations are retained, with no body, operation ID or key.

For explicit synthetic database attribution,
`PEERWORK_PARTICIPANT_QUERY_TIMINGS=1` requires a fresh protected
`PEERWORK_PARTICIPANT_HTTP_TIMINGS` output. The fixture records bounded query
verb/table hints from a fixed allowlist, lock flags, driver-await spans and
connection wait. SQL text, parameters, identifiers and errors are not exported.
Sums may include overlapping calls; the completed-span union is separately
reported. Neither is pure PostgreSQL execution time. Spans truncated or still
incomplete at response headers are explicit, and later SSE work cannot change
the completed snapshot. These observer-enabled shortened runs are diagnostic,
not a performance gate.
Fresh encrypted-body preparation now returns its already validated signed
packet to the submission driver. The driver reuses that typed candidate while
its authorization retains more than five seconds at verified service time,
instead of signing the same business request again. It still re-reads and
authenticates the durable journal winner after prerequisite work, compares all
non-time command fields, submits the original winner and verifies acceptance.
Expired candidates still take the trusted-time renewal path; a competing
ciphertext is never replaced by the preferred in-memory candidate. This is a
local candidate optimization, not a new performance or release qualification.

The optional maintainer-only `tests/qualify-agy-native-mcp.py --trace-mcp`
observer forwards the native MCP byte stream unchanged while recording bounded
fixed method/tool labels and same-host monotonic request/response times. It
never records request IDs, arguments or results. Native response availability
and harness-reported tool/model duration are distinct observations; neither
stdout forwarding nor a completed MCP call proves model consumption. This
Python diagnostic is not part of the installed native client.

The full 8KiB/100ms simulated-RTT matrix after typed-packet reuse delivered
and decrypted all495 messages, exactly495 sends and zero measured discovery,
context or journal reads. Acceptance p95 was190.25/275.48/252.12/339.79ms for
1/2/4/8 participants. The8-participant case still misses300ms; a local
packet-preparation mean reduction does not establish a tail-latency improvement.
A separate unoptimized fresh-AGY observation passed two E2EE rounds and found
roughly1.1–1.9s between harness ACTIVE observation and MCP request arrival,
versus100–175ms for non-send MCP tool responses. Reply MCP spans were1.20s
and460ms. This single session ran during compilation and does not establish
optimized percentiles, App push or an isolated host-ACK span. Temporary scoped
grants and synthetic native identity/state were removed after terminal results.

Native Windows candidates select `-C target-feature=+crt-static`. The pinned
ICU MSVC projects follow Cargo's `crt-static` target feature for both release
and debug runtime metadata; other library consumers retain their selected CRT
choice. The candidate audit rejects VC++ redistributable, Node/Python and
external ICU DLL imports. Native ICU collation is also checked against the
pinned Node24/ICU78.3 corpus on each selected target. The Windows-only candidate
at source `2cd174c2` passed native tests and installed-process qualification.
Its downloaded archive and binary hashes were verified, and its actual imports
contain only the declared Windows system DLLs/API sets, with no VC++ runtime
DLL import. This is selected-platform candidate evidence, not a public release
or qualification of the other platforms at that source.

GNU qualification now records required GLIBC, GLIBCXX and CXXABI symbol
versions as well as loader imports. The preceding audited Linux candidate
required GLIBC2.28, GLIBCXX3.4.11 and CXXABI1.3.8. It still uses the declared
system `libstdc++.so.6`; no claim of eliminating that OS dependency is made.
macOS imports must resolve to system libraries/frameworks. Toolchain runtime
notice coverage and final release packaging remain separate checks.

A qualification push marked `[native:win32-x64-msvc]` runs the changed Windows
link mode alone. Unmarked pushes/dispatches retain the three-platform matrix.
A selected-platform result never attests the whole release cohort.

For maintainer attribution only, `PEERWORK_PROGRAM_MATRIX_PHASES=1` adds
per-send completed-phase counter deltas to matrix samples. Each identity has
one sender per round; metrics snapshots sit outside its acceptance interval.
Task-local execution spans exclude separate watch/ACK work. Operation-store
counters are reported separately and must be checked for exactly one operation
before attribution. Counter resets are explicit null/non-monotonic values;
nested phases overlap and lifetime maxima are not subtracted. This mode always
disables acceptance-target qualification, even in an optimized build.

The resident-WAL source candidate's complete quiet 8 KiB / nominal100ms RTT
matrix delivered and opened all495 messages. Warm acceptance p95 for1/2/4/8
participants was183.64/196.00/240.13/286.45ms. All tails remain in the report,
including a640.50ms one-participant maximum; passing p95 does not hide that tail.
The affected native journal/participant/store and HTTP/process runs passed26
and15 cases respectively (the journal count includes a subprocess helper).
These are candidate program-transport results, not installed-tool/host or
public-network release qualification.

A separate observer-enabled matrix bounds acceptance-to-receiver-store rather
than claiming a directly measured internal span. For each matched warm message,
subtract its disjoint completed pre-POST work and a fixture-enforced minimum
uplink from that same message's call-to-receiver observation. Acceptance must
follow that pre-POST work/uplink, and observation follows durable storage, so
the remaining duration is a conservative upper bound. Cross-process timestamps
and separately calculated quantiles are never subtracted. The fixture's opt-in
`PEERWORK_FIXTURE_MIN_UPLINK=1` rechecks its monotonic timer deadline after early
wakes. `tests/fixture-delivery-bound.py` requires attributable phase counts and
retains every warm sample. In the separate495-message run, the8-participant
bound was p95<=199.39ms and p99<=240.98ms; all1/2/4/8 receiver bounds met their
250ms/1s goals. Cold samples remain separate. This does not measure host ACK or
model response, and observer runs do not qualify the quiet acceptance target.

## Selected published Node delivery evidence import (unreleased)

The native maintenance API accepts one explicit stopped-installation selection.
`peerwork runtime import-node-delivery SELECTION.json` retires that old
`ReceiverStore` constructor binding and archives its local control/delivery
records under the selected original identity. Each durable page contains at
most32 records. The command finishes pages internally; an interrupted command
resumes the same selection. `import_page` is available for a caller that owns
its own bounded maintenance loop. This is an offline operation, not a service
request or an automatic startup migration.

```json
{
  "format": "peerwork.legacy-delivery-import.v1",
  "source_directory": "/owned/stopped-node-receiver",
  "archive_directory": "/owned/native-legacy-evidence",
  "identity_path": "/owned/original-peerwork-identity",
  "expected_actor": "ORIGINAL_ACTOR_ID",
  "expected_binding_digest": "EXACT_64_HEX_OLD_CONSTRUCTOR_DIGEST",
  "kind": "RECEIVER",
  "source_stopped": true
}
```

Both directories and the selection/identity must satisfy native private-state
checks. `expected_binding_digest` is the exact old `control.binding` value;
it is not a hash of a reordered JSON configuration. Select it together with
the intended original installation, actor and host configuration. The digest
is a local selection pin, not a service signature or proof that a record is
current. A retained `receiver.lock` causes refusal: the importer never deletes
the old lock or infers process death from missing PID visibility. Stop the
original owner in its own environment before importing. Retirement changes
only the old constructor binding and adds its explicit retirement marker;
old event records and receipts stay in place. A selected recovery archive is
bounded to4096 records/32MiB and refuses further writes at capacity.

A wrong source binding is rejected before binding an empty archive. Correct
that unsubmitted selection and reuse its chosen archive directory. After an
archive has accepted pages, its exact selection remains pinned; do not change
identity, source, archive or binding to work around an interrupted import.

`kind: "BRIDGE"` additionally retains the exact original `deliveries.json`
and its at-most256 opaque bridge rows. Those old rows contain hashes but not
necessarily the original binding or message; importing them never invents a
workspace, recipient or verified native call. A later changed bridge ledger is
refused. Use the same selection for repeat/resume, without clearing old data.

`peerwork runtime legacy-evidence SELECTION.json delivery:73` decrypts exactly
one archived record. Control keys use `control:KEY`; bridge rows use
`bridge:INDEX`, with exact original ledger bytes at `bridge:original`.
Output is explicitly `LOCAL_LEGACY_EVIDENCE_NOT_REVERIFIED`. Original event
strings, status, receipt and body hash remain distinct; old `ACKED` or
`HOST_QUEUED` never becomes model completion. Unknown results remain unknown.
The archive creates no native inbox input, host call or remote acknowledgement.
Original-host receipt reconciliation and physical-session rebind still require
their separate qualified paths; this import alone does not establish them.

## Local physical binding commit (internal candidate)

The native inbox now has an internal local commit for independently verified
`native-mailbox-rebind-v1` results. It requires the original watch to be stopped,
all original reports to have been confirmed and exact old mailbox pins to match.
It preserves receiver key ciphertext, message/control cursors, encrypted frames
and original-call evidence. It accepts no unsigned remote result and performs
no host/network IO. The operator workflow that stops the runtime, uploads
reports, resumes the original signed replacement and switches host configuration
is not yet exposed as a complete SDK/CLI operation.

Pending waiting work is copied in durable pages of at most32 entries. A persisted
`COPYING` fence refuses both old and new watch attachment after interruption.
The final mailbox/watch/host pointer swap and `COMMITTED` marker share one local
transaction. Repeating that exact operation after commitment never rewrites
later cursors or state. The next ordinary restart has its own claim selection;
the verified original replacement remains a separate durable operation.

Each changed physical binding gets a distinct ordering lane generation. Old
unknown calls cannot stall a new generation, and their original input cannot
be automatically injected again. Previously unattempted waiting work keeps its
order and gets a scheduled new lane head. Original calls remain accessible by
their exact IDs and scopes. Historical facts can upload through the current
receiver lease without being attributed to the new host. A historical negative
resolution remains evidence only and does not automatically enqueue the input.

Local retirement frontiers are scoped by physical host. The old single-host
metadata table (at most256 mailbox rows) is copied once transactionally into
the new index, without reading event history; the old table remains retained.
Per-host terminal-call collection uses its own covering index instead of
filtering across unrelated historical bindings. Rebind metadata shares the
existing32MiB/65536-row host-state budget.

The service and native verifier also retain `RESULT_UNKNOWN` followed by a
bound-host `NOT_SENT` proof as two compatible observations. Neither observation
is erased; contradictory queued/accepted facts remain forbidden. This is a
recipient attestation, never a host signature or model-completion claim.

## Versioned engine-owner maintenance exclusion (internal candidate)

The operator workflow can now fence a stopped engine with
`peerwork.participant-owner.v2` before any remote replacement. The descriptor
retains the exact old logical actor/key/Origin/authority binding separately
from maintenance state. It is not an encryption pin; no journal, inbox frame,
receiver key or body key is re-encrypted when its version changes.

A pending maintenance descriptor refuses ordinary engine opening and explicit
engine transfer before store recovery or host/network startup. The error gives
the original operation ID and `RESUME_SAME_HOST_REBIND_OPERATION`. Resumption
must match the selection digest and expected owner revision. Completion retains
the v2 descriptor, so an actual pre-upgrade reader continues to refuse it after
maintenance as well. The selected new reader can reopen it normally. A stale
operation cannot clear a newer pending operation or fence an engine again after
newer maintenance has completed.

Engine transfer uses the same owner validation and copies the completed v2
descriptor exactly; it never silently downgrades the target to v1. Original
identity/journal/key paths and fixed store bindings remain unchanged. Existing
v1 owner data is accepted for this explicit upgrade; this does not add a legacy
online execution mode or fallback. Three native tests, the retained actual v1
binary refusal check and existing transfer cases are qualification evidence in
the work record, not a published release or complete rebind CLI. The public
job that couples this fence, report flushing, remote continuation, local commit
and selected host configuration update is still being integrated.
