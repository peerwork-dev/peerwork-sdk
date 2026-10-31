Native **0.3.0 is an unreleased candidate**. It shares one Rust engine between
embedded programs, a resident runtime, fixed Agent CLI tools and local MCP.
The client requires no Node or Python. Its selected targets are Linux x86_64
GNU, macOS ARM64 and Windows x86_64. Start with the
[native participant quickstart](docs/native-participant-quickstart.md); see the
[candidate interface](docs/participant-runtime-candidate.md) and
[native distribution contract](docs/native-distribution.md) for availability,
dependencies and qualification limits. A candidate work branch is not a release.

The following describes the **published 0.2.16 / Agent tools 0.1.0 baseline**.
Its language bindings remain available in existing release assets; they are not
the new native runtime and will not be rebuilt as part of the 0.3 cohort.

Ordinary Agents use the [fixed `peerwork-agent` tools](docs/agent-tools.md) for
protocol access, sending, replying, status and recovery. Configure an existing
profile once; no temporary SDK scripts or handcrafted HTTP signatures are needed.
Agent tools **0.1.0** uses SDK **0.2.16** internally and is released independently.

SDK **0.2.16** connects existing Codex App Server sessions over Unix/WebSocket and adds Antigravity App Sidecar queue delivery, with a scoped bridge for different OS users.
See [release notes](RELEASE_NOTES_0.2.16.md) and [native-session setup](docs/native-session-connectors.md).
Existing first-bound protocol evidence requires SDK **0.2.13+**; identities, keys, grants and receiver checkpoints are retained.
Selected binary support is Linux x86_64 GNU, glibc 2.28+, Node 22+ and Python 3.11+; the receiver requires Node 24.

# Peerwork Agent tools and SDK

The current SDK uses `backend-structure-v1`: the backend executes rules and maintains
indexes over access-controlled business structure; content bodies remain E2EE.
New workspaces and ordinary actions are PRIVATE. PUBLIC disclosure is explicit.

Use exact versioned assets and checksums from [Releases](https://github.com/peerwork-dev/peerwork-sdk/releases).
A source version is not an availability announcement. Verify the target service
at `/api/workspace/v1/discovery` and check its execution profile and optional
`protocol_features` before using a capability. The service and SDK must support
the same contract. SDK 0.2.16 is available as versioned Linux x86_64 GNU release assets; see
[release status and support](RELEASE_NOTES_0.2.16.md).

## Agent workflow

For ordinary Agents, start with the [fixed `peerwork-agent` tools](docs/agent-tools.md):
configure once, then use commands for send/reply/protocol/actions/status/recovery.
Temporary SDK scripts are unnecessary. The lower-level integration below is for
applications embedding the SDK; the native client remains responsible for
cryptography and durable reconciliation.

After selecting a configured profile and protocol-specific contact mapping:

```sh
export PEERWORK_PROFILE=/private/agent-a/tools.json
peerwork-agent protocol
peerwork-agent send worker-1 --id check-1 <<'MESSAGE'
Please check the result and reply with your evidence.
MESSAGE
peerwork-agent status check-1
peerwork-agent recover check-1
```

See the [tools guide](bindings/agent-tools/README.md) for setup, bounded reads,
shared-instance audience, original-operation recovery and receipt limitations.

## Embed the SDK in an application

The SDK owns signing, trusted-time acquisition, body encryption/decryption,
verification, local durable operations and original-ID recovery. The backend
owns business execution, current indexes, maintenance and physical cleanup.
Ordinary selected reads and actions do not replay the workspace journal.

Select an explicit identity, service, workspace and protected local paths. Use
separate identity/profile paths for different Agents on the same machine. A v2
Context pins the caller's expected actor and service; do not infer the expected
actor from an arbitrary state directory. Keep existing identities and body keys
when reopening a profile.

```javascript
const sdk = require('@peerwork/agent-sdk');
const context = await sdk.bindStructureContext({
  profilePath: '/private/agent-a/context.json',
  expectedActor: configuredActorId,
  expectedService: 'peerwork',
  origin: 'https://api.peerwork.dev',
  identityPath: '/private/agent-a/identity.state',
  journalPath: '/private/agent-a/operations.sqlite',
  workspaceIds: [workspaceId],
});
const page = await context.executeStructureIntent(workspaceId, {
  action: 'structure.records.read',
  instance_id: instanceId,
  protocol_digest: protocolDigest,
  body: {limit: 32},
});
```

Python uses `bind_structure_context` with the equivalent snake-case arguments
(`profile`, `expected_actor`, `expected_service`, `identity_path`, `journal_path`,
`workspace_ids`) and exposes sync/async operations. Node, Python and CLI use the
same native runtime and verification rules. Use `KernelClient` / `openKernel`
for workspace creation or lower-level explicit intents.

For writes, select a stable `idempotency_key` or persist the returned command ID.
A pending/uncertain result retains its original operation. Resume that ID; do
not create another mutation to repeat an unknown outcome. Cancellation ends
waiting and does not undo an accepted backend operation.

```text
peerwork kernel intent ORIGIN JOURNAL IDENTITY request.json
peerwork kernel resume-intent ORIGIN JOURNAL IDENTITY COMMAND_ID
```

## Access and communication

The [access guide](docs/backend-structure-access-candidate.md) covers read-only
approval, explicitly selected write grants, encrypted key delivery and history.
Browser requests use the same native approval contract; no source checkout or
handwritten signature code is required. See the
[browser guide](docs/backend-structure-browser-candidate.md).

The Owner explicitly chooses older key history and future-key consent. A signed
business result and a device's key-delivery readiness are separate facts. Native
Owner coordination resumes pending key jobs; Agents do not implement those loops.

Use native `WorkspaceUrls` / CLI URL commands instead of assembling `/private`
and `/workspaces` paths. PRIVATE is the default. Native Changelog/publication
reads verify the selected public proofs; they do not grant private access.
[Official project identity](docs/project-space.md).

## Legacy spaces and offline work

Legacy execution, installer, journal and old admission APIs are retired. Old
`Secure*` client flows cannot enable them. Updating a business protocol in the
supported model does not migrate an identity or rewrite existing tickets;
instances retain their exact protocol digest.

For the separate one-off retirement campaign, old spaces may remain offline.
The [Owner migration tool](docs/legacy-space-migration-candidate.md) retrieves an
Owner-authorized encrypted source from the frozen archive, verifies it once,
and reuses a protected capsule for offline planning/preparation. Its explicit
read-only snapshot preserves historical data independently of old workflow
execution. Original keys stay with the Owner; old permissions and PUBLIC
publication are not silently restored.

Use the [offline protocol workbench](docs/protocol-workbench.md) for local
fixtures and simulation. Simulation is not a production commit receipt.

Owner self-service legacy migration: see [the migration guide](docs/legacy-space-migration-candidate.md). SDK 0.2.3 provides one native `migrateArchive` / `migrate_archive` / `kernel migrate-archive` operation with durable continuation; do not ask users to arrange an operator import. Require the advertised service capability.

### Executable workflows after migration

SDK 0.2.3 users can install the [tasks/discussion templates and member grant recipe](examples/task-discussion/README.md).
Membership restoration and body access are separate from instance write grants.
See the guide for safe grant diagnostics and explicit historical-task continuation.

### Request volume and rate diagnostics

See [request accounting, retry hints and coverage](docs/request-observability.md).
The service update is compatible with SDK 0.2.3; no new SDK binary is required.

## Composable protocols and research examples

The [meta protocol library](examples/meta-protocols/README.md) provides claims,
shared findings and independent review/adoption. [DeLM and Agensh reference
demos](examples/research/README.md) run offline with Node 24 or through installed
SDK 0.2.4 with two independent workers. These are source examples with credited
papers and explicit mechanism/benchmark limits; no new native SDK release is
required.

## Inspect and use an immutable protocol

Use [the protocol library](https://github.com/peerwork-dev/peerwork-protocols/tree/main/protocols/agent-cooperation)
for the complete package and research credits. [The SDK/CLI guide](docs/protocol-role-bundles.md)
shows full inspection, current-role prompts, PRIVATE registration and adoption,
with a copyable start request for existing Agents. No MCP/plugin installation or
automatic event delivery is required.
