# Updating PRIVATE member permissions

The native SDK adds an Owner-bound `secure.member.scopes` producer in **0.1.10**.
It uses the service's existing commit endpoint. No service change, identity
migration, invitation or key rotation is required for an already attached Owner.
The producer supports PRIVATE wire-v3 policies, including `guard_time` with
`ALL_COMMITS`. SDK 0.1.9 and earlier do not expose this native producer.

Availability is confirmed by the exact published experimental release and its
`SOURCE.json`; a source version alone is not an available installation. See
[release notes](../RELEASE_NOTES_0.1.10.md). Experimental GitHub assets are separate
from stable npm/PyPI publication.

## Node

Use the **same selected protected Owner profile** that created or attached this
workspace. Do not create another identity to update permissions.

```js
import {randomBytes} from 'node:crypto';
import {openSecureOwnerWorkspaces} from '@peerwork/agent-sdk';

const owner = openSecureOwnerWorkspaces({
  origin: 'https://api.peerwork.dev/',
  stateDir: '/absolute/path/to/selected-owner-profile',
});
const permissions = owner.memberScopes(workspaceId);
const current = await permissions.inspect(memberActorId);
// current.instances contains verified instance IDs, actions, roles, capabilities
// and active/historical role conflicts from the decrypted installed manifests.

const operationId = randomBytes(32).toString('base64url');
// Persist this ID before calling set, and reuse it after an interruption.
const result = await permissions.set(memberActorId, {
  expectedPolicyHash: current.policy_hash,
  scopes: [{
    instance_id: selectedInstanceId,
    actions: ['claim'],                 // exact names from current.instances
    protocol_roles: ['WORKER'],
    capabilities: ['CLAIM'],
  }],
  operationId,
});
```

Replace those illustrative permission names with declarations from the selected
instance's catalog. Do not assume `claim`, `WORKER`, or `CLAIM` exist in a built-in
protocol. `set` replaces the target member's **entire** scopes list; preserve
other desired scopes explicitly. `scopes: []` revokes writes while retaining
membership, certificates and existing read/decryption keys. It does not retract
previously disclosed content or remove a member. A null `instance_id` uses the
existing workspace-wide scope semantics; select an exact instance for narrower
authority. Optional `expires_at` is an absolute millisecond timestamp.

The [runnable Node example](../examples/member-scopes/update.mjs) accepts a config
using Node field names, an existing workspace/member, a saved 43-character
base64url operation ID and a scopes JSON file. It reads the current policy and
updates it through the installed SDK; it does not sign HTTP requests in JS.

## Recovery

`set` saves the exact signed encrypted packet before POST, then refreshes verified
history. Results have `operation_id`, `command_id`, `workspace_id`, `status`,
`sequence`, `head`, and `policy_hash`.

| Status | Meaning / next step |
|---|---|
| `ACCEPTED` | Exact commit and policy were found in authenticated history. |
| `UNCHANGED` | Current scopes already match; no packet or POST was created. |
| `PENDING` | Saved operation is not yet proven accepted. Keep the ID. |
| `SUPERSEDED` | Verified history contains a different transaction in the saved packet's sequence. The original packet can no longer be accepted; inspect current policy and intentionally create a new operation if still desired. |

After timeout, HTTP refusal, cancellation or process restart:

```js
const result = await owner.memberScopes(workspaceId).recover(operationId);
// recover refreshes signed history and never POSTs.
// If PENDING, explicitly retry the immutable original packet:
const retried = await owner.memberScopes(workspaceId).retrySaved(operationId);
const saved = await owner.memberScopes(workspaceId).history();
```

`history` is local protected history, not a remote acceptance claim. Cached
accepted rows are reverified on recovery. Reusing an operation ID with different
parameters returns `MEMBER_SCOPE_OPERATION_CONFLICT`. A current policy mismatch
returns `MEMBER_SCOPE_POLICY_CHANGED` before preparation or POST. Do not replace
an unknown-outcome operation merely because of HTTP 409 or a timeout. Sanitized
HTTP diagnostics expose code, submit stage, effect certainty, retryability and
response digest; arbitrary response text is excluded.

## Python and CLI

```python
import secrets
from peerwork import SecureOwnerWorkspaceClient
owner = SecureOwnerWorkspaceClient(
    origin='https://api.peerwork.dev/',
    state_dir='/absolute/path/to/selected-owner-profile')
client = owner.member_scopes(workspace_id)
current = client.inspect(member_actor_id)
operation_id = secrets.token_urlsafe(32)  # persist before set
result = client.set(member_actor_id,
    expected_policy_hash=current['policy_hash'], scopes=[],
    operation_id=operation_id)
# client.recover(operation_id), client.retry_saved(operation_id), client.history()
# inspect_async/set_async/recover_async/retry_saved_async/history_async are available.
```

Run `peerwork member-scopes --help`. All CLI operations accept a bounded regular
JSON file containing exactly `{ "config": ..., "input": ... }`. Config uses
Python/Rust field names (`origin`, `state_dir`). Input examples:

```json
{"workspace_id":"WORKSPACE_ID","actor_id":"MEMBER_ACTOR_ID"}
```

Use that input with `member-scopes inspect`. For `set`, add
`expected_policy_hash`, the complete `scopes` array and the saved `operation_id`.
For `recover` or `retry`, input contains `workspace_id` and `operation_id` only.
For `history`, input contains `workspace_id` only. Real workspace, actor and
operation IDs are 43-character base64url tokens; policy hashes are 64 lowercase
hex characters. Raw keys and unknown fields are rejected.

## Verification boundaries

Only the authenticated Owner may replace scopes. Native preflight verifies the
current complete origin-bound replay, exact policy hash, active keyring,
declared actions/roles/capabilities, and active/historical role conflicts.
Membership order and length, certificates, Owner, epoch, guard policy, structure
contract and protocol bindings remain unchanged. Structured updates have an
empty DELTA. Guard context is included **before** AEAD and signature creation;
the service signs admission time. This administrative action adds no business
lease expiry or narrow browser-clock deadline.

`protocolCompatibility({requiredProducers: ['secure.member.scopes']})` reports
local producer support; it is not a service capability proof. Scope replacement
requires an already usable Owner profile and PRIVATE wire v3. Seeding structure
and pending key transitions are refused. A workspace retains at most 128 local
scope-update rows (4 MiB total); source replay has the profile's usual budgets.
Copies of a state directory do not establish distributed exactly-once behavior.

Installed-package acceptance runs against an isolated real synthetic service and
checks Node/Python/CLI, guarded update, exact scope-only changes, unchanged keys,
revoked and restored member writes, stale/invalid refusal, response loss,
read-only recovery and exact-packet retry. These tests do not modify production
workspaces or independently validate every external deployment.
