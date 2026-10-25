# Backend structure Context (unreleased candidate)

This document describes modified SDK source, not the published 0.1.11 package.
The matching backend execution profile is also a source candidate. No production
availability or legacy-workspace conversion is implied.

## Responsibility and trust

`backend-structure-v1` keeps business structure readable to the backend under
PRIVATE membership and grant checks. Content bodies remain opaque authenticated
ciphertext. Predicates and effects cannot read those bodies. The backend executes
business rules and maintains current records and event indexes. SDKs sign intent
and verify the service result and the original authors' signatures; ordinary
reads do not independently replay business history. Their explicit assurance is
`BACKEND_CURRENT_STATE`.

An explicit `peerwork.agent-context.v2` configuration selects this contract.
It uses an existing local identity and a protected Kernel operation store. It
does not require a legacy Owner profile, decrypted history, historical receipts,
or identity/key migration to select another backend-profile workspace. Membership
and grants must already be authorized by that workspace's Owner. Binding a local
Context grants no remote authority.

The configured HTTPS origin is the initial trust input. The first online call
pins its discovery in the local operation store; subsequent calls enforce
discovery continuity. Opening or binding a Context is offline and does not claim
that remote membership, capabilities or service health have been checked.

Legacy v1 contexts and their online readers are retired. Their identities and
historical bytes remain intact offline; selecting v2 never silently upgrades
or discloses them. Existing legacy PRIVATE workspaces require the explicit
[Owner checkpoint conversion](owner-checkpoint-conversion-candidate.md), whose
selected canary qualification is separate from ordinary Context binding.

## Bind once, reopen normally

The identity and protected parent directories must already exist. Bind never
overwrites a file, creates an identity, or changes workspace membership. Paths
may be absolute, or relative to the Context file. A journal is created and its
discovery pinned when the first online operation needs it.

```javascript
const context = await sdk.bindStructureContext({
  profilePath: '/protected/worker/context.json',
  expectedActor: workerActorId,
  expectedService: 'peerwork-production',
  origin: controlOrigin,
  identityPath: '/protected/worker/identity.state',
  journalPath: '/protected/worker/operations.sqlite',
  workspaceIds: [workspaceId],
});
```

```python
context = peerwork.bind_structure_context(
    profile='/protected/worker/context.json',
    expected_actor=worker_actor_id,
    expected_service='peerwork-production',
    origin=control_origin,
    identity_path='/protected/worker/identity.state',
    journal_path='/protected/worker/operations.sqlite',
    workspace_ids=[workspace_id],
)
```

Reopen using `openContext` / `open_context`. Handles automatically include the
opened configuration fingerprint on subsequent operations. Identity, source,
workspace selection or authority changes require explicitly reopening the
Context. Journal cursors and accepted operations do not change the fingerprint.
Different agents on one machine should select their own protected identities and
operation stores; a shared machine does not imply a shared actor.

## Selected reads and one business operation

```javascript
const page = await context.discover(workspaceId, {limit: 16});
const selected = page.result.instances[0];
const current = await context.describe(workspaceId, {
  instanceId: selected.instance_id,
  protocolDigest: selected.protocol_digest,
});

const outcome = await context.operate(workspaceId, {
  kind: 'protocol.action',
  instance_id: selected.instance_id,
  protocol_digest: selected.protocol_digest,
  expected_instance_revision: current.result.revision,
  action_id: 'claim',
  values: {},
  refs: [],
}, 'claim-ticket-42');
```

The SDK supplies signing metadata, authorization time from a nonce-bound signed
service context, signature, transport and verification. The Agent does not issue
BEGIN/PAGE/END or rebuild history. One SDK call may make discovery, authorization
and command requests and at most two mutation attempts. Typed maintenance also
uses bounded selected progress reads automatically. After transient synchronous
mutation reply loss, one indexed observation of the exact original operation is
attempted within the same call when its time budget permits. A failed or missing
observation preserves the original pending packet; it never proves non-commit.
The intent driver deadline
is 30 seconds; discovery has a separate bounded transport timeout. These bounds
are recovery safeguards, not a production latency SLO.

`operate` owns the idempotency key using its `operationId`. Repeating the same
operation and business fields recovers the same result. A changed revision,
authority, target, input, reference or ciphertext conflicts; the SDK never
silently rebases an operation onto a newer state. A signed deterministic business
rejection returns `status: 'rejected'` with `REJECTED_NO_EFFECT`. A verified
successful result returns `status: 'verified'`.

For adoption, member/grant administration or any explicit read, use the same
bounded intent vocabulary through `executeStructureIntent(workspaceId, intent)`
or Python `execute_structure_intent(workspace_id, intent)`. Python also provides
the async variant. `operate` accepts `{kind: 'structure.intent', request: intent}`
when a stable operation ID should be supplied separately.

## Pages and events

```javascript
const records = await context.executeStructureIntent(workspaceId, {
  action: 'structure.records.read',
  instance_id: selected.instance_id,
  protocol_digest: selected.protocol_digest,
  body: {schema: 'ticket', limit: 16},
});
const tail = await context.executeStructureIntent(workspaceId, {
  action: 'structure.events.read',
  body: {},
});
const changes = await context.executeStructureIntent(workspaceId, {
  action: 'structure.events.read',
  body: {after_sequence: tail.result.checkpoint, limit: 16},
});
```

Pages use signed keyset cursors, with at most 32 results and a separate response
size budget. Shared original-author signatures are counted and loaded once per
selected page, rather than repeated for every record from that operation. Use `next_cursor` unchanged as `body.cursor`; `discover` accepts it
as `after`. Default record pages are current LIVE pages, not a historical
snapshot. Merge events after the first page's `observer_checkpoint` to account
for concurrent changes, including newly inserted keys before a traversed key.
`consistency: 'IF_UNCHANGED'` explicitly requests rejection if the instance view
changed between pages.

An event read without `after_sequence` starts NOW. Reading all retained events
requires explicitly selecting `after_sequence: 0`; no subscription implicitly
fetches the entire history. Event pagination fixes an upper frontier; finish
its cursor chain, then poll from the returned checkpoint. These are bounded
event queries, not a durable consumer lease or push subscription. V1 replay
methods such as `eventsSync` are unavailable for v2 and never used as a fallback.

Fresh reads are verified in memory and do not save every page in the mutation
outbox. Explicit `command_id` or `idempotency_key` selects durable historical read
reuse. Writes are saved before submission. This distinction avoids a local
archive growing with every ordinary event poll or page read.

## Uncertain delivery and recovery

```javascript
if (outcome.status === 'pending') {
  const recovered = await context.recover(workspaceId, {
    commandId: outcome.command_id,
  });
}
// The original caller operation ID is also supported:
const recovered = await context.recover(workspaceId, {
  operationId: 'claim-ticket-42',
});
```

Recovery authenticates the selected saved command and checks its workspace
before resubmitting it. An A operation cannot be resumed through B. It never
enumerates all pending operations. Expired mutation authorization can be renewed
with unchanged business intent and ciphertext. The original author packet and
immutable service outcome remain verifiable after renewal.

For an ordinary read with `recovery: 'NEW_READ'`, issue a fresh read; it has no
saved mutation to resume. A missing operation observation does not prove that a
concurrent request can never commit. Preserve the original key after uncertainty.

## CLI

```sh
peerwork context bind-structure CONTEXT ACTOR SERVICE CONFIG_JSON_FILE
peerwork context open CONTEXT ACTOR SERVICE
peerwork context execute-structure CONTEXT ACTOR SERVICE REQUEST_JSON_FILE
peerwork operate CONTEXT ACTOR SERVICE REQUEST_JSON_FILE
peerwork context recover CONTEXT ACTOR SERVICE REQUEST_JSON_FILE
```

`bind-structure` accepts the v2 configuration emitted by the SDK helper.
`execute-structure` accepts `{workspace_id, intent, expected_fingerprint}`.
Keep the fingerprint returned by open/bind when invoking separate CLI processes.

Canonical [browser routing and access](backend-structure-browser-candidate.md) now have local Chromium and installed-package qualification. Complete PUBLIC workflows, automatic historical-key handoff and broader migration/release qualification remain unfinished. Body transport is bounded to64KiB per body and action. Canonical
current-key rotation and SDK-owned distribution are described in the
[key lifecycle workflow](backend-structure-content-keys-candidate.md). Source-level and local installed-artifact tests do not constitute a release
or production qualification.

The implemented `CURRENT_RECORDS` maintenance job is described in
[Backend maintenance](backend-structure-maintenance-candidate.md). It uses an
immutable admission plus separately signed completion observations; an accepted
admission alone does not claim that background work has completed.

## Owner-authorized access

Contexts now expose `requestAccess`, `authorizeAccess` and `acceptContentKeys`
(Node), with snake_case and asynchronous equivalents in Python. Selected reads
automatically retrieve missing recipient-bound body keys. See the
[access workflow and release limitations](backend-structure-access-candidate.md).

See [terminal outcomes and recovery](backend-structure-outcomes-candidate.md) for
confirmed refusal, temporarily restricted committed results and uncertain delivery.


`rotateContentKey` and `coordinateContentKeys` (Python snake_case and async
variants) own the entire current-key delivery workflow. A verified result means
its backend delivery job is complete. For pending `KEY_DELIVERY`, use the
returned continuation or repeat the original high-level call; generic recovery
of the publication alone does not claim that distribution finished. The SDK
retains selected delivery stages across process restarts, without journal-history
replay or Agent-managed recipient loops.

## Durable preparation and recovery

The source candidate now persists encrypted native preparation plans before remote
crypto prerequisites. Node, Python and CLI resume them by the original command ID;
local pending pages also expose bounded preparation locators. See
[durable structure operations](backend-structure-parent-operations-candidate.md)
for phases, shared call budgets, storage bindings and remaining key-delivery limits.
