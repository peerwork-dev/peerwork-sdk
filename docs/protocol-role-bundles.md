# Protocol rules and role instructions in one package

SDK 0.2.5 provides the helpers below. Install the matching exact-version native
package and use a service advertising `protocol-role-bundles-v1`. Release assets
and live service discovery establish availability.

## Contract

A `peerwork.protocol-bundle.v1` is an immutable package containing a normalized
`backend-structure-v1` manifest, every declared role's Markdown instructions,
typed action bindings, resources, dependency package digests and source credits.
The package digest binds all of these. The execution digest continues to bind
only the manifest, so changing a prompt changes the package digest without
changing the business rules. Existing instances retain their selected package.
No identity, key or history migration is required for a new protocol package.

Role instructions are visible to authorized workspace members. Private business
bodies remain E2EE. Do not put secrets in instructions or structural fields.
An instruction describes how an Agent should cooperate; it does not authorize a
shell, change its host environment or guarantee model compliance. Backend guards
and current grants remain the enforcement mechanism for submitted actions.

Inspecting returns every authorized role/resource, not just the current role.
A runtime role read checks current membership, grant, expiration and role, and
returns that role's instructions plus tools filtered by granted action IDs.
`granted_actions` does not imply that an action's business guards currently pass.

## Node

```javascript
const sdk = require('@peerwork/agent-sdk');
const kernel = await sdk.openKernel({
  origin: 'https://api.peerwork.dev',
  identityPath: '/private/worker-a/identity.state',
  journalPath: '/private/worker-a/operations.sqlite',
  requiredFeatures: ['protocol-role-bundles-v1'],
});
if (kernel.actor_id !== expectedActor) throw Error('IDENTITY_MISMATCH');
const protocols = sdk.protocols(kernel);

// Local authored hashes and package contract, no HTTP request.
const summary = sdk.inspectProtocolBundle(bundle);

// Owner: register privately without creating an instance or enabling anything.
const registered = await protocols.register({
  workspace_id, bundle, idempotency_key: 'register-my-protocol-v1',
});
// Owner: one durable adoption intent; registration can also be inline in adopt.
const adopted = await protocols.adopt({
  workspace_id, package_digest: summary.package_digest,
  idempotency_key: 'adopt-my-work-unit',
  bootstrap_grant: {
    actions: ['work.claim', 'work.renew', 'work.submit'],
    protocol_roles: ['WORKER'], capabilities: ['CLAIM', 'SUBMIT'],
  },
});

// All authored rules, roles, resources and credits in one signed read.
const inspected = await protocols.inspect({workspace_id, instance_id});
// Current selected role + its prompt + currently granted typed tools.
const outcome = await protocols.role({workspace_id, instance_id, role: 'WORKER'});
if (outcome.state === 'PENDING') {
  // Preserve this envelope; resume with protocols.resume(outcome.command_id).
} else if (outcome.state === 'ACCEPTED' || outcome.state === 'COMPLETED') {
  const view = outcome.result.structure;
  if (view.package_digest !== expectedPackageDigest) throw Error('PACKAGE_CHANGED');
  const instructions = view.resources[view.runtime.instructions_resource].content;
  // Supply this instruction text through your existing Agent's prompt/context.
  // Invoke permitted business actions through kernel.executeStructureIntent.
}
```

The Node and Python bindings use the same native verifier. It checks the service
receipt, requested selection, package root, resource hashes and Owner-authored
registration/adoption source. A fresh service signature cannot substitute a new
prompt or tool declaration without matching Owner evidence. Current-state and
grant results retain the existing `BACKEND_CURRENT_STATE` trust boundary.

Every helper preserves the SDK outcome envelope. An uncertain mutation resumes
the same command, never a replacement operation. One signed role read includes
the selected prompt: no per-resource request loop or workspace-history replay.
Discovery/service-time requests are still part of the native transport workflow.

## Python

```python
from peerwork import KernelClient, ProtocolClient, inspect_protocol_bundle
kernel = KernelClient(origin, journal_path, identity_path,
    required_features=('protocol-role-bundles-v1',))
assert kernel.open()['actor_id'] == expected_actor
protocols = ProtocolClient(kernel)
summary = inspect_protocol_bundle(bundle)
view = protocols.role(workspace_id, instance_id, 'WORKER')
inspection = protocols.inspect(workspace_id, instance_id=instance_id)
```

`register`, `adopt` and `resume` have the same meaning as the Node helpers.
Use explicit identity and space selections. Several Agents on one machine do
not share an implicit current user. Separate identities when independent
attribution or permissions are needed; keep their protected state directories
separate. A session may explicitly select several spaces. Confidentiality
isolation also requires avoiding unrelated private data in the same model context.

## CLI

```sh
peerwork bundle inspect bundle.json
peerwork kernel protocol-inspect ORIGIN JOURNAL IDENTITY selection.json
peerwork kernel protocol-role ORIGIN JOURNAL IDENTITY role.json
peerwork kernel protocol-register ORIGIN JOURNAL IDENTITY registration.json
peerwork kernel protocol-adopt ORIGIN JOURNAL IDENTITY adoption.json
peerwork kernel resume-intent ORIGIN JOURNAL IDENTITY COMMAND_ID
```

`selection.json`: `{"workspace_id":"...","instance_id":"..."}`.
`role.json` additionally selects `"role":"WORKER"`.
Registration selects `workspace_id`, `bundle` and `idempotency_key`; adoption
selects `workspace_id`, exactly one `bundle` or `package_digest`, a stable
`idempotency_key` and optional `bootstrap_grant`. All wrappers use the native
intent/recovery implementation. CLI JSON outputs preserve refusal/PENDING states.

## Authoring and limits

The public protocol repository contains the ready-to-inspect artifacts and role source in
[`protocols/agent-cooperation`](https://github.com/peerwork-dev/peerwork-protocols/tree/main/protocols/agent-cooperation).
The Backend's `scripts/build-protocol-role-bundles.mjs` uses the actual Backend
manifest normalizer/compiler before emitting packages and their digest lockfile.
Use it after compiling the workspace. Local native inspection verifies package
shape/hashes; it is not a second business-rule interpreter. The actual compiler
and offline evaluator establish business-rule validity.

Bounds per package: 114,688 canonical UTF-8 bytes, 32 resources, 8,192 bytes per
resource, 32 roles, 32 tool bindings per role and 16 dependency roots. Resource
paths are logical bundle paths, never filesystem/URL fetch instructions.
Dependencies pin registered workspace package roots; they do not implicitly
compose rules, inherit permissions or execute code. Resolve composition into
the manifest at authoring time. Registration requires dependency roots to exist
in the same workspace; no recursive network fetch occurs.

Private registration and instance adoption are distinct from public publication.
There is no implicit public catalog publication. This change does not introduce
an Agent runtime, plugin, MCP server, listener or automatic delivery. See the
[deferred delivery plan](protocol-event-delivery-plan.md).

## Validation and availability

Acceptance covers real HTTP/PostgreSQL with native Node/Python/CLI: full and role
reads, source/resource verification, response-loss recovery, immutable instance
binding, access revocation, transaction rollback, additive schema migration and
bounded workspace deletion. It does not establish model-quality gains, a
paper's reported benchmark score or automatic use by an unmodified Agent.
A release must publish matching SDK assets, deploy the advertised service feature
and add the official public Changelog before describing this as available.

## Start an existing Agent

Copy and fill this request in the Agent conversation. It uses existing tools;
it does not install a Skill, plugin, MCP server or background listener:

> Use Peerwork protocol PACKAGE_DIGEST in WORKSPACE_ID / INSTANCE_ID as ROLE.
> My objective and acceptance checks are: GOAL_AND_CHECKS. Use the explicitly
> selected existing client identity EXPECTED_ACTOR. Inspect the complete package
> and load the granted role instructions through the official SDK/CLI. Confirm
> the package/actor/space binding before writing. Choose actions from the role's
> current granted tools, keep private bodies encrypted, and resume uncertain
> submissions under their original IDs. Verify the result against my acceptance
> checks. If no usable signing client is available, report that prerequisite;
> do not infer access from a public link or modify my Agent configuration.
