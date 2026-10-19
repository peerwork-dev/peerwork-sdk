# Bounded PRIVATE leases using trusted transaction time

This guide covers the `time-add-guard-window-v1` expression profile on top of
`signed-private-guard-time-v1`. It expresses bounded acquisition, renewal and
reclaim using the same signed transaction admission time **T**. The expiry is
an encrypted client input; the service does not generate or decrypt business
fields. A complete generic example is provided below. Application protocols,
participant permissions and external fencing remain the integrator's choices.

## Service and SDK support

| Surface | Minimum supported contract | Availability |
| --- | --- | --- |
| Service attestation | `signed-private-guard-time-v1` | Existing signed admission-time contract; workspace activation is explicit. |
| Bounded expression profile | `time-add-guard-window-v1` | Check `GET https://api.peerwork.dev/api/workspace/v1/guard-time-capabilities`; `effects` must be `TIME_FREE`. This is separate from legacy discovery. |
| Native Python, Node and CLI | **0.1.4 experimental** | Experimental native 0.1.4 artifacts are distributed through [SDK releases](https://github.com/peerwork-dev/peerwork-sdk/releases). Match the exact version and SOURCE.json; the [live guide](https://peerwork.dev/docs/private-guard-time) pins the qualified build. Version 0.1.3 and earlier do not provide this complete workflow. |
| TypeScript implementation | `SecureAgentClient.enableGuardTime`, `action`, `resumeGuardTimeAction` | The platform source includes the matching implementation and executable example. No published TypeScript npm version is implied. |

The profile reuses the v1 signed interval and attestation wire formats. The new
capability is checked explicitly; do not infer arithmetic support just from the
older discovery feature. The native SDK exposes `owner_guard_time_enable` and
`private_time_add_guard_windows` in its capabilities.

## What T means

**T is `admitted_at_ms` in the service-signed guard-time attestation.** The
service obtains it while admitting the exact commit in its database transaction,
checks the signed inclusive guard interval and rejects clock rollback. The
attestation binds the service audience/key, workspace, actor/key, command,
action, instance, epoch, policy hash, source and result checkpoints, commit hash,
interval and admission timestamp. SDK replay verifies those bindings and that
the encrypted action's derived interval is exactly the signed interval.

Client wall time, `issued_at`, an HTTP Date header and a preflight timestamp do
not authorize a lease. A client may propose `expires_at` using its local clock;
skew or network delay can cause rejection, while the service's actual T remains
authoritative. The example uses local time only for proposals and scheduling.

## Native expression

For fixed, reviewed integer milliseconds `0 < MIN_TTL <= MAX_TTL`, use:

```json
[
  {"op":"lte","left":{"from":"time_add","timestamp":{"from":"time"},"milliseconds":{"from":"literal","value":1000}},"right":{"from":"body","path":["expires_at"]}},
  {"op":"gte","left":{"from":"time_add","timestamp":{"from":"time"},"milliseconds":{"from":"literal","value":60000}},"right":{"from":"body","path":["expires_at"]}}
]
```

This means `1000 <= expires_at - T <= 60000`. The SDK derives the inclusive
interval `[expires_at - 60000, expires_at - 1000]`, intersected with the safe
integer timestamp domain. The service tests its actual admission time against
that exact interval. All time arithmetic must remain safe: every `time_add`
operand and result is an integer in `[0, 9007199254740991]`. An overflowing
`T + MAX_TTL` is rejected even if an unbounded mathematical comparison would be
true. Bounds are not silently rounded or saturated.

Nested `time_add` in the timestamp operand is supported when each milliseconds
operand is time-free and nonnegative. Direct and reversed `lt/lte/gt/gte`
comparisons and conjunctions are supported. Time on both comparison sides,
time in the milliseconds operand, timed equality/OR/NOT, multiple variants in
a timed action and effects that read T remain unsupported and fail preflight.
Time-free arithmetic uses the ordinary checked evaluator.

Effects copy `body.expires_at` to encrypted state. They never calculate a value
from T after the payload has been encrypted.

| Operation | Additional conditions |
| --- | --- |
| Claim | The selected old state permits acquisition; require its expected generation, assign a strictly newer generation, and apply the MIN/MAX guards. |
| Renew | Current holder and generation; `T < old_expires_at`; `new_expires_at > old_expires_at`; apply MIN/MAX to the new expiry. |
| Reclaim | Expected old generation; `T >= old_expires_at`; assign a strictly newer generation and apply MIN/MAX to the new expiry. |
| Use | Current holder and generation; `T < expires_at`. |

A fresh generation fences old work only where it is checked. Downstream systems
must compare the generation before external effects; admission time alone does
not revoke a process's ability to perform outside work.

## Owner activation through the native SDK

Start with the selected existing protected Owner and a verified current policy.
The service audience and receipt key below must already be trusted and pinned.
Do not copy a signing seed, epoch key or arbitrary untrusted discovery value.

```python
import secrets
import peerwork

owner = peerwork.SecureOwnerWorkspaceClient(origin, protected_owner_state_dir)
before = owner.read(workspace_id)
operation_id = secrets.token_urlsafe(32)  # persist before calling enable
control = owner.guard_time(workspace_id)
result = control.enable(
    expected_policy_hash=before["policy_hash"],
    audience=pinned_audience,
    service_key=pinned_receipt_public_key,
    disclosure="GUARD_WINDOW",
    operation_id=operation_id,
)
if result["status"] == "PENDING":
    result = control.resume(operation_id)
assert result["status"] in ("ACCEPTED", "ALREADY_ENABLED")
```

`expected_policy_hash` is a compare-and-swap precondition. Activation requires
PRIVATE policy v3, the exact Owner, a fully verified source, an active keyring
without a pending transition, matching pinned discovery and explicit disclosure
consent. It signs the new Owner policy and `secure.guard-time.enable` ADMIN
commit and sends `{commit, policy_update}` to
`POST /api/workspace/v1/secure/workspaces/{workspace_id}/commits`.

The native operation persists its exact encrypted packet before POST. A lost
response is not permission to generate another identity, policy or operation.
Reopen the same Owner state and call `guard_time(workspace_id).history()` to
recover IDs, then `resume(original_operation_id)`. Recovery independently
verifies acceptance or retries the identical saved packet at its unchanged
source. A changed source or changed operation input fails explicitly.
`history()` is local inventory; a local PENDING row is not remote acceptance.

Python has `enable_async`, `resume_async` and `history_async`. Node uses
`owner.guardTime(workspaceId).enable({expectedPolicyHash, audience, serviceKey,
disclosure: 'GUARD_WINDOW', operationId})`, plus `resume`/`history` and
`AbortSignal`. CLI uses `peerwork guard-time enable|resume|history REQUEST.json`;
`peerwork guard-time --help` gives the complete `{config,input}` envelope.

## Existing spaces, old clients and signer rotation

Activation writes an explicit `ALL_COMMITS` guard-time policy. Every subsequent
commit, including ADMIN and time-free actions, carries a signed time context;
time-free actions use the universal interval. It does not rewrite history:
commits under older policies retain their original validation rules.

All writers must understand the enabled timed policy. Writers executing the new
`time_add` protocol need native SDK 0.1.4 or the matching TypeScript
implementation. Older guard-time clients can still understand their previous
direct-deadline protocols; they cannot execute or semantically replay this new
arithmetic profile. Native writers perform full workspace replay: once an arithmetic action exists,
all native writing clients in that workspace need the new SDK, even when their
own action is time-free. Upgrade participants that need to write or audit it
before adopting it. Unsupported clients must reject, never ignore the new semantics.

The policy pins the service audience and receipt public key. Repeating the
same activation at the same current policy is idempotent; replacing those pins
is rejected. Automatic in-place signer rotation is not implemented. Preserve
the pinned verification key for historical attestations, and plan an explicit
supported migration before any signer change.

PRIVATE content remains E2EE. The service observes the explicitly disclosed
admission interval and existing approved structure, not the plaintext lease
fields. Use full verified SDK replay when validating business transitions;
`SERVICE_STRUCTURE_SELECTION` current-page reading verifies selected authors
but does not claim complete historical semantic validation.

## Complete runnable example

The example directory setup is tested on Linux. Native Windows SDK support does
not make this script a Windows ACL provisioning tool; prepare private Windows
state using the SDK's documented ACL requirements before adapting the example.

Download the matching files from the public example endpoints listed below,
install the exact native release above, and follow the included README:

- [Python example](https://peerwork.dev/docs/examples/private-bounded-lease/run.py)
- [Installable package closure](https://peerwork.dev/docs/examples/private-bounded-lease/closure.json)
- [Package and compiled-protocol pins](https://peerwork.dev/docs/examples/private-bounded-lease/package-pins.json)
- [Resolved manifest](https://peerwork.dev/docs/examples/private-bounded-lease/manifest.json)
- [Run and recovery instructions](https://peerwork.dev/docs/examples/private-bounded-lease/README.md)

The generic example creates a synthetic PRIVATE workspace with its own
protected Owner, explicitly enables time disclosure, installs the selected
package, claims, renews, reclaims and rejects an old generation. It is not a
production task-dispatch protocol or a ready-made permission policy. Reuse your
existing identity/source when integrating into an existing workspace.

The platform source repository additionally includes a TypeScript runner and
offline expression preflight; those product-source files are not part of this
native SDK checkout. Tests cover both inclusive TTL boundaries
and adjacent rejected milliseconds, renewal before/at expiry, non-increasing
expiry, reclaim before/at expiry, stale generations, arithmetic overflow and
invalid bounds, changed checkpoints, recovery after an accepted response is
lost, and substituted admission proofs. Scripted protocol/HTTP acceptance is
separate from natural-Agent workflow compliance.
