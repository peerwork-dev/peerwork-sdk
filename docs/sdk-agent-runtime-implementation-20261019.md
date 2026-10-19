# Agent context implementation checkpoint — 2026-10-19

Status: existing-state context binding and scoped action-receipt delivery are
implemented in source. T282 native focused checks: **16 passed**. Final installed
cohort 03 (session `58566`): **PASS**, reconciled exit 0. Exact source/archive,
artifacts and assertions: `.test-data/t282-sdk/verification.json`. This is a
bounded A/B/E slice of the [canonical design](sdk-agent-runtime-design-20261019.md),
not completion of its install → bind → approval → action → communication loop.
Source presence does not establish public release availability, installed target
qualification or natural-Agent acceptance. Use only an artifact that actually
exports these interfaces; the older public experimental package is not evidence
of their availability. Current validation results belong to the accompanying
implementation/release evidence, not this API description.

T283 native PRIVATE workspace browser approval passed **3 core checks**, **20
runtime checks**, and installed browser-protocol approval/redemption/decryption
with installed Node/CLI recovery parity. These remain scoped synthetic-service
results; they do not establish Chromium UI or natural-Agent workflow acceptance.
T284 discovery/exact description and the unchanged-checkpoint probe have **24
passing native checks** and **first-attempt installed discovery/events PASS**
through fresh wheel, npm and CLI artifacts. One fresh natural-Agent trial passed
business correctness and workflow after a preserved model-capacity interruption
and stale-lease recovery; it is not a first-attempt complete workflow pass. The
Agent read the exact entry/protocol, recovered the original accepted command,
verified member authorship, acknowledged three receipts and saved a native-wait
continuation. Exact evidence: `.test-data/t284-sdk/verification.json`.

## Implemented boundary

Python `bind_context`, Node `bindContext` and CLI `context bind` explicitly create
a new protected context reference from caller-selected existing workspace
profiles. Validation precedes the no-overwrite write; identity, membership and
workspace state are not created or copied. Python `open_context`, Node
`openContext` and CLI `context open` select an
existing identity and existing PRIVATE member read/action state. Opening is
local, noncreating and nonenrolling. The adapter validates protected profiles,
identity, service, workspace and existing decryption history; it neither copies
keys nor substitutes Owner authority. Every subsequent call rechecks bindings.
Python and Node handles also retain the opening fingerprint and refuse profile
binding drift with `CONTEXT_CHANGED` before effectful work.

Supported operations are `discover`, `describe`, `inspect`, `operations`, `operate` for
`protocol.action` and `browser.approve`, `recover`, and scoped `events.sync/receive/ack/status`. Inspection returns verified state and saved
pending actions. `discover` and `describe` provide the bounded installed
protocol/action and exact-reference projection described below.
`operations` lists unresolved saved actions, not a complete audit history.
Typed action values and exact refs are serialized by the shared core; callers
do not construct signed/encrypted envelopes.

`recover` reconciles one existing command, selected by exactly one stable
operation ID or command ID. It does not run an autonomous retry/continuation
loop. A pending result retains its original command identity; do not create a
replacement intent to obtain a successful exit. Reusing an operation ID with
changed intent conflicts. Canonical object key ordering preserves equivalent
intent values. The current source binds a supplied operation ID for PRIVATE
actions with or without guard-time policy. Guarded PRIVATE actions still require
an ID; existing unguarded calls that omit an ID retain their previous behavior.
The context interface requires an ID on every new action.

Historical unguarded action rows may lack an operation-ID association even when
the caller supplied one to the older implementation. Recover those rows using
their original command ID, discovered through pending operations if necessary;
this adapter does not backfill an association or resubmit a replacement action.
The affected installed compatibility flow passed in T281 on Linux x86_64 GNU
using a pinned synthetic reference service. It is not current-PROD or release-CI
qualification. Exact artifacts, source hashes and retained failures are recorded
in `.test-data/t281-sdk/verification.json`.

Results preserve the native `peerwork.agent-result.v1` schema, safe context,
status, operation identity, raw operation result and available evidence,
receipt/effect refs and continuation. `pending` is not verified acceptance.
`verified` actions carry exact command-bound receipt/effect evidence. Python
`AgentContextError` and Node `AgentContextError` preserve the safe native error
envelope, code, layer, effect certainty and continuation. Cancellation propagates
to native work and cannot undo accepted remote effects. CLI stdout contains the
JSON envelope, and failures use a nonzero exit.

## Bind existing profiles; advanced compatibility schema

Use `bind_context`/`bindContext`/`context bind` below to create the context
reference without handwriting a new context JSON document. Existing protected
workspace profiles and admitted state remain prerequisites; this is not new
identity setup or enrollment. Select existing authorized files explicitly; do
not discover keys by scanning, copy PEM files, invent a state root or fabricate
saved history. Existing membership, recipient keys, `read.profile` and
`lifecycle.state` must already be valid for the selected workspace.

The following schema remains an advanced compatibility option for manually
supplied context references and describes the existing workspace configuration.
Keep these files inside an owner-protected directory, with private file permissions (on Unix, directory mode 0700 and files 0600). References
may be absolute or relative to the containing profile; parent traversal and
unsafe files are refused. These illustrative values must be replaced with the
operator-selected real values.

`context.json`:

```json
{
  "schema": "peerwork.agent-context.v1",
  "service_id": "selected-environment",
  "origin": "https://peerwork.example/",
  "identity_path": "identity.state",
  "workspaces": {
    "WORKSPACE_ID": {
      "profile_path": "member-workspace.json",
      "visibility": "PRIVATE"
    }
  }
}
```

`member-workspace.json` uses the existing `SecureReadProfileConfig` shape:

```json
{
  "origin": "https://peerwork.example/",
  "state_dir": "/selected/existing/member-state",
  "identity_path": "identity.state",
  "workspace_id": "WORKSPACE_ID",
  "owner_actor_id": "EXPECTED_OWNER_ACTOR",
  "owner_key_id": "EXPECTED_OWNER_KEY"
}
```

Use the existing configured authority, feature and transport settings where
applicable; selected settings must match saved profile/history bindings. An
explicit `allow_loopback_http: true` on both profiles permits a configured local
loopback test service; it does not permit general plaintext HTTP. `service_id`
is the caller's selected environment label, checked alongside the origin and
saved trust bindings. It is not server-issued authority.

## Installed interface examples

Values below are caller-selected identifiers and schema-valid business values.
Retain one stable operation ID for the intended action. The operation-ID contract
accepts 1–128 ASCII letters, digits, `-`, `_` or `.`; it does not require decoding
canonical base64url bytes. Inspect the actual installed
protocol and grants before acting. These examples do not choose a protocol,
create membership or authorize an action.

```python
import peerwork

# Once, using a new target path under an existing protected directory:
ctx = peerwork.bind_context(profile=PROFILE, expected_actor=ACTOR,
    expected_service=SERVICE, workspace_profiles=[EXISTING_WORKSPACE_PROFILE])
# Later processes reopen; bind refuses to overwrite an existing target.
ctx = peerwork.open_context(profile=PROFILE,
    expected_actor=ACTOR, expected_service=SERVICE)
view = ctx.inspect(WORKSPACE)
pending = ctx.operations(WORKSPACE)
result = ctx.operate(WORKSPACE, {
    "kind": "protocol.action", "instance_id": INSTANCE,
    "action_id": ACTION, "values": VALUES, "refs": EXACT_REFS,
}, OPERATION_ID)
# After uncertainty or restart, reopen the same profile and reconcile the same ID.
result = ctx.recover(WORKSPACE, operation_id=OPERATION_ID)
```

Python provides `inspect_async`, `operations_async`, `operate_async` and
`recover_async`; cancellation uses the native cancellation token.

```javascript
// Once; the target context file must not already exist.
await sdk.bindContext({profilePath: PROFILE, expectedActor: ACTOR,
  expectedService: SERVICE, workspaceProfiles: [EXISTING_WORKSPACE_PROFILE]});
const ctx = await sdk.openContext({profilePath: PROFILE,
  expectedActor: ACTOR, expectedService: SERVICE});
const view = await ctx.inspect(WORKSPACE);
const result = await ctx.operate(WORKSPACE, {
  kind: 'protocol.action', instance_id: INSTANCE, action_id: ACTION,
  values: VALUES, refs: EXACT_REFS,
}, OPERATION_ID);
const recovered = await ctx.recover(WORKSPACE, {operationId: OPERATION_ID});
```

Node methods accept an options object with `signal` for native cancellation.

```sh
peerwork context --help
peerwork context bind PROFILE ACTOR SERVICE bind.json
peerwork context open PROFILE ACTOR SERVICE
peerwork context inspect PROFILE ACTOR SERVICE inspect.json
peerwork operate PROFILE ACTOR SERVICE action.json
peerwork context recover PROFILE ACTOR SERVICE recover.json
```

`bind.json` contains `{"workspace_profiles":["/selected/existing/member-workspace.json"]}`.
The target parent must already be protected; bind refuses to overwrite an
existing target. Referenced paths are resolved against the target context parent.
`inspect.json` contains `{"workspace_id":"WORKSPACE_ID"}`. `action.json` contains
`workspace_id`, `operation_id` and the ordinary `intent` object shown above.
`recover.json` contains `workspace_id` and exactly one of `operation_id` or
`command_id`. For continuity across separate CLI invocations, include
`expected_fingerprint` from `context open` in each request. Python/Node handles
inject this automatically. Input files contain ordinary JSON, not nested JSON
strings or signature packets. Help is offline and identifies unsupported
producers.

## Discover protocol shape and read exact references

`discover` returns verified workspace metadata, checkpoint, selected actor and a
bounded installed-instance/action index. Use optional `after` and `limit` (up to
128) to follow its continuation. The SDK does not choose a protocol or action.
An entry protocol is reported as declared only when the verified source declares
one; `entry.status: "not_declared"` is not permission to invent an entry rule.
Follow the operator's exact entry reference when supplied.

`describe` supports three mutually exclusive queries: instance plus optional
action, exact record ID plus semantic revision, or exact object reference
`{kind,id,revision}`. Object-reference revisions refer to the authenticated
outer object; record revisions refer to the record's semantic revision used by
action refs. Missing exact history is refused, never replaced with latest data.

Instance/action description returns the exact instance and protocol reference,
manifest/resolved manifest, selected action, schemas and source/composition
metadata where present. Discover action summaries use `action_id`; the exact
manifest action in describe uses `id`. Scope/grant summaries are advisory at the
reported checkpoint. `execution: "not_evaluated"` means dynamic predicates and
the proposed business operation have not been evaluated or authorized merely
by discovery. Service validation remains authoritative.

```python
index = ctx.discover(WORKSPACE, limit=64)["result"]
# Choose an intended instance/action from the verified index.
description = ctx.describe(WORKSPACE, INSTANCE, action_id=ACTION)["result"]
entry = ctx.describe(WORKSPACE, record_id=ENTRY_RECORD_ID,
                     revision=ENTRY_REVISION)["result"]["object"]
```

Python also provides `discover_async` and `describe_async` with cancellation.

```javascript
const index = (await ctx.discover(WORKSPACE, {limit: 64, signal})).result;
const description = (await ctx.describe(WORKSPACE,
  {instanceId: INSTANCE, actionId: ACTION, signal})).result;
const entry = (await ctx.describe(WORKSPACE,
  {recordId: ENTRY_RECORD_ID, revision: ENTRY_REVISION, signal})).result.object;
```

```sh
peerwork context discover PROFILE ACTOR SERVICE discover.json
peerwork context describe PROFILE ACTOR SERVICE describe.json
```

Requests contain `workspace_id`, selected `expected_fingerprint` and `query`.
Discover query is optional, for example `{"limit":64}`; description queries are
`{"instance_id":"INSTANCE","action_id":"ACTION"}`,
`{"record_id":"RECORD","revision":1}`, or
`{"object_ref":{"kind":"records","id":"RECORD","revision":1}}`.
These are generic selectors; no preset-specific helper or full-object dump is
required to find action schemas or read the selected entry record.

## Native PRIVATE workspace browser approval

The caller supplies the exact compact reference copied from the intended browser
and an explicit write-consent choice. The native producer fetches and checks the
request against that reference and selected context, prepares secure delegation
and PRIVATE key delivery, persists the operation, submits and verifies signed
acceptance. It does not invoke the product's TypeScript approval helper, require
a source checkout, grant membership or substitute another actor. Admission-browser
approval is a separate workflow and is not covered here.

```python
approved = ctx.operate(WORKSPACE, {
    "kind": "browser.approve", "reference": EXACT_BROWSER_REFERENCE,
    "approve_writes": False,
}, APPROVAL_OPERATION_ID)
# On an uncertain reply or a later process:
approved = ctx.recover(WORKSPACE, operation_id=APPROVAL_OPERATION_ID)
if approved["status"] == "verified":
    private_code = approved["result"]["approval_code"]
    # Deliver privately to the intended browser through the authorized channel.
```

```javascript
let approved = await ctx.operate(WORKSPACE, {
  kind: 'browser.approve', reference: EXACT_BROWSER_REFERENCE, approve_writes: false,
}, APPROVAL_OPERATION_ID);
approved = await ctx.recover(WORKSPACE, {operationId: APPROVAL_OPERATION_ID});
if (approved.status === 'verified') {
  const privateCode = approved.result.approval_code;
  // Deliver privately; do not log the result or code.
}
```

CLI uses `peerwork operate PROFILE ACTOR SERVICE approval.json`, with the same
`workspace_id`, `operation_id` and `intent` fields; recovery uses `context recover`
and the original operation ID. CLI JSON output includes the sensitive code after
verified acceptance, so capture it through an appropriately protected channel
rather than a public transcript or routine log.

Only `ACCEPTED` with `verification: "verified"` releases `result.approval_code`.
`browser_consumption: "pending"` remains explicit: the browser must redeem the
code and prove it can use its approved scope. Pending/uncertain results do not
release a code. Preserve the supplied continuation and recover the same operation;
never create a replacement approval to get past uncertainty. Stable IDs cannot
be reused between protocol actions and browser approvals. Expired unresolved
operations retain uncertainty rather than re-signing or broadening consent.

The code is a sensitive one-time credential, not material for a workspace post,
public Page, telemetry or an ordinary log. `approve_writes: false` refuses a
request containing writes; explicit `true` does not bypass the member's actual
scope or authorize a different device, origin, reference or request. Membership
and action grants remain independently required.

## Scoped action-receipt delivery

The only source is `verified-action-receipts/v1`: receipts derived from native
authenticated action replay, with structured `delivery.receipt` containing exact
command, actor, commit and effects. Canonical receipt text is retained as an
expert exactness field; normal callers need not decode packets or byte arrays.
This does not cover arbitrary journal, admission, browser or external events.

The durable event inbox currently has a Unix-only storage implementation
(Linux/macOS); Windows event storage returns `UNSUPPORTED_PLATFORM`. This is a
feature boundary, not a rejection of every other Windows SDK capability.
`context.events.platform_supported` describes the compiled storage path and is
added after fingerprint calculation, so capability reporting does not invalidate
existing contexts, pending operations or inbox bindings. A `true` value still
requires valid protected paths and does not establish installed qualification for
every Unix target. Non-Unix tests assert the unsupported result rather than
pretending that inbox delivery ran.

`events_sync` / `eventsSync` / `event-sync` use an authenticated unchanged-checkpoint
probe after initialization: a signed journal request starts at the saved sequence
with limit 1. Matching checkpoint/owner/policy binding, no commits and no next
page establish the cheap unchanged path. Discovery and policy metadata can still
cost network/verification work; this is not a zero-request idle claim. A changed,
missing or mismatched probe falls back to full authenticated history replay.
Initial synchronization also replays full retained history. `incremental` remains
`false`; reader semantics are `checkpoint_probe_then_full_history_replay`.
Results identify `sync_path: "checkpoint_probe"` with `probe: "unchanged"`, or
`sync_path: "full_history_replay"`. No incremental changed-history replay or
fixed-latency promise is implied. A batch is limited to 256 events and the inbox to 10,000 retained events
(with additional payload bounds). Capacity or source-gap failures stop progress;
there is no automatic eviction or retention compaction. An acknowledged event
remains retained. The caller-selected `filter_version` is a subscription version
label, not a content-filter engine.

Consumers have independent acknowledgements. Unacknowledged leases may redeliver
after expiry or restart; exact event identity remains stable while lease tokens
change. Acknowledgement records local delivery acceptance, not protocol task
completion, and a signed event does not authorize execution. Source status,
acknowledgement and zero-wait receive use an initialized pinned local inbox
without network access. Positive-wait receive first returns queued delivery
locally; an empty queue refreshes through native replay/polling. If the local
source is not initialized, synchronize explicitly. Gap refusal preserves the
queue and acknowledgement positions for explicit recovery.

Receive accepts lease durations from 1 to 3,600,000 milliseconds and a requested
wait budget from 0 to 60,000 milliseconds. Defaults in Python/Node are a 30-second
lease and zero wait. Waiting uses cooperative native cancellation, not a strict
hard-wall deadline guarantee. Timeout returns a continuation; cancellation does
not acknowledge a delivery or undo a previously accepted business action.

```python
ctx.events_sync(WORKSPACE)
result = ctx.events_receive(WORKSPACE, CONSUMER,
    filter_version="all-v1", lease_ms=30000, wait_ms=1000)
delivery = result["result"]["delivery"]
if delivery is not None:
    receipt = delivery["receipt"]  # inspect; choose any business action separately
    ctx.events_ack(WORKSPACE, CONSUMER, delivery["ack_token"], filter_version="all-v1")
status = ctx.events_status(WORKSPACE)
```

All four Python event methods also have `_async` variants. Native cancellation
is propagated when an asyncio task is cancelled.

```javascript
await ctx.eventsSync(WORKSPACE);
const received = await ctx.eventsReceive(WORKSPACE, CONSUMER,
  {filterVersion: 'all-v1', leaseMs: 30000, waitMs: 1000, signal});
const delivery = received.result.delivery;
if (delivery !== null) {
  const receipt = delivery.receipt;
  await ctx.eventsAck(WORKSPACE, CONSUMER, delivery.ack_token,
    {filterVersion: 'all-v1', signal});
}
const status = await ctx.eventsStatus(WORKSPACE, {signal});
```

```sh
peerwork context event-sync PROFILE ACTOR SERVICE workspace.json
peerwork context event-receive PROFILE ACTOR SERVICE receive.json
peerwork context event-ack PROFILE ACTOR SERVICE ack.json
peerwork context event-status PROFILE ACTOR SERVICE workspace.json
```

Each request names `workspace_id` and should carry the selected
`expected_fingerprint`. `receive.json` also names `consumer_id`,
`filter_version`, `lease_ms` and `wait_ms`; `ack.json` names `consumer_id`,
`filter_version` and the returned `ack_token`. CLI help gives complete ordinary
JSON shapes. Avoid logging lease tokens or PRIVATE receipt content.

## Resume a continuation without changing its meaning

Current continuations describe a next operation; they are not complete executable
requests. Preserve the selected profile, actor, service, workspace and opening
fingerprint in the protected handoff. For CLI calls, choose the named verb
(`events.receive` maps to `context event-receive`), then build its ordinary request
from the descriptor's applicable fields. Do not copy `operation` into request
JSON. A receive also needs the caller-selected `lease_ms` and `wait_ms` budgets;
include the retained `expected_fingerprint` on every request. CLI omission remains
accepted for legacy compatibility and does not pin cross-process continuity.
Python/Node handles inject their opening fingerprint automatically; reopening a
handle establishes a new pin, so compare it with the retained handoff fingerprint
before resuming if continuity across the restart is required.

For an action, call `recover` with exactly one original operation or command ID.
For a receive deadline, use the same consumer and version with a newly bounded
wait. A lease may expire while work is interrupted: `STALE_LEASE` requires receiving
again and using the newly returned token, not replaying the expired acknowledgement.
`ok:true` and CLI exit zero alone prove neither action acceptance nor delivery;
check the action verification evidence or receive's `delivery`/`wait_status`.

The caller still maps continuation fields and reinvokes the method. An executable
`resume(continuation)` is an explicit ergonomic backlog item, not a delivered API.
It should share core validation across Python/Node/CLI, preserve exact bindings,
allow only supported continuations, retain legacy interfaces and safely handle
expired leases without introducing a replacement business mutation.

## Remaining A–E work

| Design package | This slice | Remaining work |
| --- | --- | --- |
| A: result/operation contract and delivery | Shared adapter and three binding surfaces | Qualify exact installed artifacts and publish a scoped release; broaden result/capability parity |
| B: context continuity | Explicit bind of existing profiles, preflight and pinned handles | Initial identity/admission setup, full context composition/migration, wider concurrency qualification |
| C: complete platform intents | PRIVATE workspace browser approval producer and common saved-operation recovery in source | Actual browser UI qualification beyond the passing synthetic redemption/decryption flow; admission-browser producer and typed destructive intents |
| D: discovery/composition | Bounded verified discover, protocol/action/schema description and exact-reference reads | Wider projection qualification beyond the passing installed cohort; dependency composition and installation through common operations |
| E: communication | Durable action-receipt inbox, leases/ack, native wait and local buffered delivery | Incremental transport/replay, additional sources, retention/compaction, broader Agent handoff and scale qualification beyond the single preserved trial |

Admission-browser approval, general notification/watch runtime,
incremental sync, PUBLIC context action support and all-platform qualification
remain outside this slice. Existing specialized clients remain available.
Installed scripted tests and natural-Agent workflow acceptance are separate:
measure intended identity/source/protocol/recovery behavior independently of
signed business correctness, retaining failed attempts and implementation gaps.

## Remaining delivery work

Changed history still requires full authenticated replay; unchanged initialized
sources use a bounded checkpoint probe. True incremental replay, non-ACTION
event sources, remaining platform producers (including workspace deletion and
admission workflows), fresh enrollment/cold-start journeys, platform/scale
qualification and public package publication remain open in the canonical
design. No public release or current-PROD SDK qualification is implied.

### T285: verified delta remains incomplete

Source review confirmed that the current reader and core verifier cannot resume
verification from their rendered replay result. The bounded next work and proof,
crash, recovery and acceptance requirements are in
[Verified cross-poll delta](sdk-verified-delta-plan-20261019.md).
No delta runtime change or new delta acceptance claim was made in this review.

## T285 combined review and bounded backlog correction

Final local cohort 01 passed 5 affected core checks, 25 runtime checks and fresh
installed Python/Node/CLI discovery/events and browser-approval recovery
regressions. More than 256 pending ACTION receipts now progress in bounded
batches using exact checkpoints projected from the fully verified chain; each
transaction advances only through included receipts. A 300-receipt native
regression covers two batches and intervening non-ACTION commits. This is not
true incremental verification or removal of the 10k/64MiB retained-inbox limit.
Exact artifacts/source and outcomes: `.test-data/t285-sdk/verification.json`.

The member-first entry guide now links specialized Owner prerequisites
conditionally. CLI help documents fingerprint pins, continuation mapping and
lease expiry. The T284 natural-Agent result remains bound to its frozen task,
entry and artifact; no new trial qualified the revised default guide or this
cohort. No public release or production write occurred.
