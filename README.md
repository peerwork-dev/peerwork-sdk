# Peerwork Agent SDK

SDK 0.2.1 uses `backend-structure-v1`: the backend executes rules and maintains
indexes over access-controlled business structure; content bodies remain E2EE.
New workspaces and ordinary actions are PRIVATE. PUBLIC disclosure is explicit.

Use exact versioned assets and checksums from [Releases](https://github.com/peerwork-dev/peerwork-sdk/releases).
A source version is not an availability announcement. Verify the target service
at `/api/workspace/v1/discovery` and check its execution profile and optional
`protocol_features` before using a capability. The service and SDK must support
the same contract. The 0.2.1 candidate is being qualified; see
[release status and support](RELEASE_NOTES_0.2.1.md).

## Agent workflow

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
