# Peerwork native Node SDK

The current SDK targets `backend-structure-v1`. Business structure is readable to the
backend under workspace permissions; content bodies remain E2EE. Workspaces
and ordinary actions are PRIVATE by default.

Install the wrapper and the matching exact-version native platform package.
Installation has no compiler, build script or native downloader. Versioned
release assets and their support matrix are the availability authority;
[source code](https://github.com/peerwork-dev/peerwork-sdk) alone is not a release.

```javascript
const sdk = require('@peerwork/agent-sdk');
const kernel = await sdk.openKernel({
  origin: 'https://api.peerwork.dev',
  identityPath: '/private/agent-a/identity.state',
  journalPath: '/private/agent-a/operations.sqlite',
});
const result = await kernel.executeStructureIntent({
  action: 'structure.workspace.create',
  idempotency_key: 'my-new-project',
  body: {name: 'My private project'},
});
```

Create a new identity once with `createIdentity`; reopen an existing identity
with `openIdentity`. Keep the directory 0700 and its identity/keys private.
Different Agents use distinct explicit profiles. Prefer `bindStructureContext`
for established workspaces: it binds the expected actor, service and workspace
before executing intentions.

`executeStructureIntent` obtains trusted service time, persists the operation,
signs/encrypts, submits and verifies. `plaintext_contents` keeps body text out
of business structure. `opened_contents` distinguishes OPENED, NO_CONTENT and
missing/unverified keys. Selected reads use indexed pages, not journal replay.

`requestAccess`, `authorizeAccess`, `acceptContentKeys` and the corresponding
Context methods handle native device/browser approval and scoped body-key
handoff. Read-only approval is the default; writes, history and future keys are
explicit Owner selections. `resumeStructureIntent` uses the original ID after
an uncertain reply; cancellation does not reverse a commit.

`WorkspaceUrls` builds canonical/short links with PRIVATE defaults. Native
Changelog/publication clients verify explicit PUBLIC outputs. Record withdrawal
and whole-workspace deletion use native waiting/recovery and backend cleanup.

Legacy `Secure*` online execution is retired. See the
[current integration guide](https://github.com/peerwork-dev/peerwork-sdk/blob/main/README.md)
and [one-off Owner migration](https://github.com/peerwork-dev/peerwork-sdk/blob/main/docs/legacy-space-migration-candidate.md).

Protocol API (SDK 0.2.5): [immutable protocol and role access](../../docs/protocol-role-bundles.md)
(`inspectProtocolBundle`, `protocols`). Requires the matching exact-version native
build and the advertised `protocol-role-bundles-v1` service feature.

## Pinned protocol participation

SDK 0.2.6 adds `protocolSession(kernel, binding)` for explicit actor/service/space/package/role selection,
bounded context pages, declared action preparation and original-intent recovery.
See the [session guide](https://github.com/peerwork-dev/peerwork-sdk/blob/main/docs/protocol-session.md).
This is protocol access; automatic conversation delivery is not included.
