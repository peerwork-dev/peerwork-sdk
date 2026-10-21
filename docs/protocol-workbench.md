# Local protocol development and recoverable execution

These interfaces are introduced in native SDK **0.1.9 experimental**. Use the exact
release assets and their `SOURCE.json` / `SHA256SUMS`; a checkout is not an installed
release. Python, Node and CLI use the same Rust protocol evaluator and recovery
implementation. No service deployment or identity replacement is required.

## Keep protocol versions independent

Publishing a new manifest does not change an existing instance's pinned protocol
digest. Install the new version as a separate instance and direct new tickets to
it. Existing tickets continue on their original version. Publishing a protocol,
importing a historical client identity, and converting a business ticket are
separate operations with separate acceptance criteria.

Conversion is optional. Define an explicit mapping and protocol actions for it;
the SDK does not infer business consent or rewrite existing records. A conversion
that transfers claim authority must close or fence the old authority before
activating the new one. Multiple commits or instances are not one atomic
transaction. Preserve exact source record IDs and revisions in the new record.

## Start without a service

The [standalone example](../examples/protocol-workbench/offline.py) creates v1 and
v2 fixtures, validates an explicit source-reference mapping, rejects a bad source
revision, and tests the bounded-lease manifest locally:

```sh
python3 examples/protocol-workbench/offline.py
```

It needs only the installed wheel and the example files. It creates no identity,
opens no socket, and does not submit anything. A completely synthetic fixture is
sufficient; production data is not a prerequisite.

```python
from peerwork import build_protocol_fixture, simulate_protocol, plan_protocol_actions

fixture = build_protocol_fixture(
    [{"instance_id": "candidate", "manifest": manifest}],
    actors=[{"name": "worker", "workspace_role": "MEMBER",
             "protocol_roles": ["WORKER"], "capabilities": ["CLAIM"]}],
    seed="local-case", time_ms=1000,
)
steps = [{"instance_id": "candidate", "action_id": "claim", "body": values}]
result = simulate_protocol(fixture, steps, seed="local-case")
plan = plan_protocol_actions(fixture, steps, seed="local-case")
```

Use the roles and capabilities actually needed by your protocol. The fixture
builder does not infer or grant missing roles. Each step can explicitly set
`actor_id` (fixture name or exact actor ID), `time_ms`, `exact_input_refs`,
`allocations` and `expected_instance_revision`. Simulation defaults are
deterministic; `time_ms` is a test input, never a claim about platform time.
Test expiry boundaries, missing permissions, stale generations, absent exact
references, multiple actors, and release-before-activation order before a canary.

Results contain `simulated: true`, `authoritative: false`, input/output state,
effects, assumptions and per-step diagnostics. Failure identifies `code`, `stage`,
`step`, `action_id` and `constraint`. A failed sequence does not modify the input
fixture or return a partially advanced fixture. A simulation is not a signed
receipt or evidence of authorization on a real workspace.

## Export selected real state once, then iterate offline

An existing native context already selects the identity, service and workspace:

```python
fixture = context.export_fixture(workspace_id, [old_instance, new_instance],
                                 time_ms=test_time_ms)
# After that verified read, no service is needed for local simulation/planning.
result = simulate_protocol(fixture, steps)
plan = plan_protocol_actions(fixture, steps)
# Reuse the existing local checkpoint without HTTP:
cached = context.export_fixture(workspace_id, [old_instance, new_instance],
                                time_ms=test_time_ms, cached=True)
```

The native read verifies signatures, E2EE decryption, pinned identity/policy and
history. Export projects the selected instances and their protocols, records,
entity heads and relevant authorization from that verified read. It exports no
private signing or recipient key. Real exports and plans contain decrypted
business data: save them only in protected local files. Unselected instance
content is omitted; policy membership is retained for authorization evaluation.

Cached export verifies the existing local snapshot; it does not establish current
server freshness. Fresh export currently uses the existing verified read engine
and may replay history. Local iteration requires no repeated reads. This release
does not claim an incremental network synchronization redesign.

The lower-level `SecureReadClient.export_fixture` and
`export_protocol_fixture(profile, instance_ids, time_ms=...)` are also available.
Use a separate protected state directory for each selected principal, service and
workspace. Share an identity only intentionally; independent copied operation
stores do not provide distributed logical-operation deduplication.

## Revalidate, apply and resume the same plan

```python
result = context.apply_plan(workspace_id, plan, "convert-ticket-42-v1")
# The native SDK stores the exact plan before its first submission.
# After PENDING or a process stop, no handwritten packet or plan reconstruction:
result = context.resume_plan(workspace_id, "convert-ticket-42-v1")
```

Plans pin the engine version, selected protocol/state dependencies, actor,
concrete record allocations, exact references, revisions and intermediate
frontiers. Before a new submission the SDK reads and verifies current state,
checks dependencies, evaluates the step again and pins the authored instance
revision. The service remains authoritative about authorization, trusted time
and commit acceptance. Synthetic plans are refused for online apply.

The original canonical plan is saved in protected native state and bound to the
common operation namespace. `context.operations(workspace_id)` lists unresolved
plans without disclosing their fixture content. Default `context.recover` returns
read-only local progress and a continuation; it does not submit a plan. Explicit
`resume_plan` continues the same saved plan and may submit its remaining steps.
Changing a plan under the same root ID is refused.

Online apply belongs to one selected identity. Split workflows involving several
actors into separately authorized plans and handoffs; the SDK does not adopt
another actor to execute a step.

Each step uses a durable child operation. Exact saved packets are reconciled
before preparing another packet. A crash or lost reply does not authorize a new
operation ID. Accepted receipts and progress persist before the next step.

| Result | Meaning and next action |
| --- | --- |
| `VERIFIED` | All steps have verified signed-history acceptance and the checked final frontier matches. |
| `PENDING` | The current exact operation is unresolved. Resume the same plan and operation ID. |
| `PLAN_STALE` | A dependency changed before the next new submission. Inspect `completed_steps`, `results` and the dependency hashes; export and review a plan for the remaining work. |
| `PLAN_OUTCOME_CHANGED` | A step was accepted, but the verified state differs from the offline prediction, or changed afterward. Its accepted receipt remains in `results`. Inspect it before planning further. |

The SDK never silently rebases a business conversion or erases an accepted
effect. A fixed plan is conservative: policy/member changes can invalidate it.
Platform transaction time can differ from a chosen simulation time; effects that
depend on time or concurrent writes can therefore require a reviewed remaining
plan. Prefer explicit expiry values with time guards, as in the bounded-lease
example. Online execution is not a reservation of the simulated state.

## Invitation completion and safe recovery

```python
intent = {"kind": "workspace.invitation.finalize", "invite_id": invite_id}
result = context.operate(workspace_id, intent, "admit-worker-42")
result = context.recover(workspace_id, operation_id="admit-worker-42")
```

PRIVATE finalize binds the authenticated policy's guard-time context before
encryption/AAD and signatures. Time-independent ADMIN operations use the existing
wide guard context; there is no new short browser or invitation deadline.
Invitation expiry, consent, scope and current authority are still checked.

Default recovery only reconciles. For an exact saved malformed finalize from an
older native SDK, select its `saved_grant_id` in the original intent. The SDK
authenticates its policy, signatures, invitation/ACCEPT and full history before
reporting `REPLACEMENT_SAFE`. Only an intrinsically inadmissible missing-guard
packet under the immutable guarded policy qualifies. HTTP 409 or an absent record
alone never qualifies. All original packet bytes remain unchanged.

```python
result = context.recover(workspace_id, operation_id="admit-worker-42",
    recovery={"mode": "safe", "max_submissions": 1})
```

This authorizes one exact retransmission **or** one proven-safe successor, within
the original identity and consent. Unknown acceptance remains unresolved. It is
not a general facility to replace expired actions or repair arbitrary legacy
packets. A verified historical result is labeled `HISTORICAL_CHECKPOINT` on cached
recovery; it does not assert that membership is still active now.

## Compatibility and diagnostics

```python
from peerwork import protocol_compatibility
report = protocol_compatibility([
    "protocol.action", "protocol.install", "workspace.invitation.finalize",
    "owner.guard_time.enable", "owner.guard_time.resume",
])
```

This reports local producer coverage and exact SDK version. Unknown producers
remain `unknown`; it does not verify the remote service or other writers.
Guard activation accepts `required_producers` and refuses an unsupported declared
producer before submission. Existing calls without this optional field retain
their prior contract. Declare every required writer, maintenance and recovery
path, qualify their installed versions, and check authenticated discovery before
enabling `ALL_COMMITS`. One working action does not prove all clients are ready.

HTTP rejections expose bounded, allowlisted `code`, `stage`, `constraint`,
`http_status`, `effect_certainty`, `retryability`, a response digest and recovery
hints through the Context envelope. Arbitrary response text is not copied into
default diagnostics. Unknown failures preserve uncertainty; do not infer
nonacceptance from a response status.

## Node and CLI equivalents

Node exposes `buildProtocolFixture`, `simulateProtocol`, `planProtocolActions`,
`exportProtocolFixture`, `applyProtocolPlan` and `protocolCompatibility`. Existing
contexts provide `exportFixture(workspaceId, {instanceIds, timeMs, cached})` and
`applyPlan(workspaceId, plan, operationId)` / `resumePlan(workspaceId, operationId)`.
`resumeProtocolPlan` and Python `resume_protocol_plan` support explicit profiles.
Node uses native workers and supports
`AbortSignal`; Python provides asynchronous variants for service operations and
simulation. Cancellation cannot retract an already submitted packet.

```sh
peerwork protocol --help
peerwork protocol compatibility compatibility-request.json
peerwork protocol fixture fixture-request.json
peerwork protocol simulate simulation-request.json
peerwork protocol plan simulation-request.json
peerwork protocol export export-request.json
peerwork protocol apply apply-request.json
```

CLI requests are UTF-8 JSON files, bounded to 4 MiB. `fixture` requires
`schema: "peerwork.protocol-fixture.v1"`, `protocols` and optional `actors`, `seed`,
`time_ms`. `simulate` and `plan` require
`schema: "peerwork.protocol-simulation.v1"`, `fixture`, `steps` and optional `seed`.
`export` takes `profile`, `instance_ids`, explicit `time_ms` and optional `cached`.
`apply` takes `profile`, `plan` and `operation_id`. To explicitly resume a saved
plan, omit `plan` and retain the original `operation_id`. Success is `{ok:true,value:...}`;
refusals are typed JSON with nonzero exit. Inspect `status`; exit zero alone does
not establish completion.

## Supported boundary

This release supports self-contained native manifests using the existing
`peerwork.kernel.v1` evaluator, exact record references and explicit fixture
actors/time. Unresolved dependencies, composed/resolved manifests requiring
extra execution proofs, and related legacy grants/record relations are refused
with typed unsupported errors instead of being omitted. Budgets include 64 steps,
4096 fixture objects, 128 policy members and 4 MiB per request/plan. This is not
general migration of arbitrary historical SDK state, an automatic conversion
policy, or distributed exactly-once execution.
