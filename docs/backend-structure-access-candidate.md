# Backend structure access

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

## Agent-facing workflow

Use a v2 Context that selects the service, signing identity, protected local
paths and workspace. Separate Agents use separate identity/profile paths even
when they share a machine. Do not copy another Agent's local state directory.
An ordinary access request does not import identity history or migrate a client.

```javascript
// worker and owner are explicitly selected v2 Contexts.
const pending = await worker.requestAccess(workspaceId, {
  label: 'Research worker',
});

const approval = await owner.authorizeAccess(workspaceId, {
  request_jws: pending.result.request_jws,
  ttl_ms: 24 * 60 * 60 * 1000,
  include_history: true, // explicitly include older workspace bodies
  follow_current_key: true, // explicit permission for future current-key deliveries
});

const page = await worker.executeStructureIntent(workspaceId, {
  action: 'structure.records.read',
  instance_id: instanceId,
  protocol_digest: protocolDigest,
  body: {limit: 32},
});
```

Approval defaults to read-only membership and delivery of the Owner's current
body key. Future epochs are excluded unless `follow_current_key: true` is
explicitly selected; this option requires content-key delivery and remains bound
to the approved membership generation and recipient certificate. Session lifetime defaults to 24 hours and cannot exceed 31 days or
the recipient certificate's expiry. The service enforces expiry; the label is
presentation only. A renewed session has a fresh membership generation, so its
previous write grants do not silently become valid again.

The SDK owns request signing, recipient certificates, encryption, verification,
local persistence and retry handling. The backend receives readable structure,
public certificates and recipient-bound encrypted key boxes. It receives no
recipient private key, plaintext body key, or plaintext content body.

Python Contexts expose `request_access`, `authorize_access` and
`accept_content_keys`, plus asynchronous equivalents. Advanced Kernel clients
expose the corresponding methods with `workspace_id` inside the selection.
The CLI uses JSON selection files:

```text
peerwork kernel access-request ORIGIN JOURNAL IDENTITY request.json
peerwork kernel access-approve ORIGIN JOURNAL IDENTITY approval.json
peerwork kernel content-keys ORIGIN JOURNAL IDENTITY selected-keys.json
```

Plain HTTP is restricted to explicitly enabled loopback development, using
`--allow-loopback-http` in the CLI. Production uses the selected HTTPS origin.

## Explicit selected write permission

A requester can name one desired instance/protocol/action in its `write`
selection. Approval remains read-only unless the Owner explicitly supplies the
matching `selected_write`, with chosen protocol roles and capabilities:

```javascript
const pending = await worker.requestAccess(workspaceId, {
  label: 'Ticket worker',
  write: {instance_id: instanceId, protocol_digest: digest, action_id: 'claim'},
});
await owner.authorizeAccess(workspaceId, {
  request_jws: pending.result.request_jws,
  selected_write: {
    instance_id: instanceId, protocol_digest: digest, action_id: 'claim',
    protocol_roles: [], capabilities: [],
  },
});
```

The service atomically applies membership, selected permission and opaque key
delivery. The Owner cannot accidentally approve a different requested action
through this entry point. This does not grant every action or every manifest
role. Browser requests use the same wire contract with `kind: 'BROWSER'` and
browser-held keys. The [browser candidate](backend-structure-browser-candidate.md) now has real Chromium qualification, including first-use Owner pinning, signed key-epoch floors and restart recovery; deployment remains pending.

`mode: 'KEYS_ONLY'` delivers selected keys to an already active member without
renewing membership or changing its permissions. It does not accept `ttl_ms`
or `selected_write`. `deliver_content_keys: false` permits structural access
without claiming that encrypted bodies are readable.

## Bounded automatic key retrieval

After a selected record/page read, the SDK identifies at most 32 missing body
key IDs. It fetches only their public grant metadata and the required original
Owner signatures, verifies recipient/workspace/service bindings and every key
commitment, then imports verified material atomically. Oversized proof responses
explicitly defer selected IDs. The SDK follows these bounded selections; it
never scans workspace history or rebuilds workspace state.

A missing delivery does not hide readable structure. Each body reports its own
state, including `OPENED`, `KEY_UNAVAILABLE`, `KEY_GRANT_INVALID` or
`KEY_DELIVERY_UNAVAILABLE`. Successfully opened bodies carry
`AUTHOR_SIGNATURE_AND_AEAD` assurance. Current structural state separately uses
`BACKEND_CURRENT_STATE`; this is not independent full-history verification.

Explicit `acceptContentKeys` accepts `owner_id` and selected `key_ids` for a
caller-pinned Owner. An optional `current_key_id`, guarded by
`expected_current_key_id`, selects a current writing key. Automatic historical
key retrieval never overwrites a newer local current key.

## Time and recovery

The ten-minute human approval window comes from a nonce-bound, service-signed
time context. Request creation does not read browser wall time. A public
self-certificate proves possession of the request's signing key; it does not
confer workspace authority.

Owner approval computes an operation ID before creating the random encrypted
key box. The SDK durably saves one exact signed packet before submission.
Repeating the same approval selection resumes that operation, including after
the original human approval window expires. It does not create a fresh key box
or silently rebase the workspace revision. A known business rejection requires
an explicit new selection; an uncertain outcome requires reconciliation of the
original operation.

## Remaining release work

The installed npm package, wheel and CLI have completed a synthetic cross-Agent
handoff, body opening, selected write, signature-corruption rejection, committed
reply-loss recovery and expired-request reconciliation. Preferred Node and Python Context facades have passed those same installed-package
operations, including Python asynchronous request creation and cross-workspace
selection rejection.

The candidate is not ready to deploy. [Canonical key epochs and rotation](backend-structure-content-keys-candidate.md) now have installed-package qualification. Automatic recipient fan-out and restartable Owner-side coordination also have installed-package qualification. The [browser candidate](backend-structure-browser-candidate.md) has installed-SDK/Chromium qualification. Automatic historical-key handoff, PUBLIC flows and the remaining migration/release work are still required. Body transport is bounded to64KiB per body and action; larger-file transport is separate work. Signed terminal refusals, restricted commit acknowledgments and structured
preflight diagnostics are implemented; see [outcome recovery](backend-structure-outcomes-candidate.md).

## Durable preparation and recovery

The source candidate now persists encrypted native preparation plans before remote
crypto prerequisites. Node, Python and CLI resume them by the original command ID;
local pending pages also expose bounded preparation locators. See
[durable structure operations](backend-structure-parent-operations-candidate.md)
for phases, shared call budgets, storage bindings and remaining key-delivery limits.

## Automatic crypto prerequisites

The Owner SDK now automatically repairs an expired or revoked key head before a
new key-bearing approval. The normalized approval remains its durable parent;
unknown crypto publication results are resumed through that parent. Head
publication does not grant historical keys or imply that recipient delivery is
complete. The default remains current-key-only with explicit future-key consent.
See [canonical key epochs](backend-structure-content-keys-candidate.md) for the
independent native Owner key worker.

An Owner may now explicitly request `include_history: true`. This signs an epoch
ceiling and creates a separate resumable delivery job. The native SDK reports
`key_history` readiness separately from the approval receipt. See
[retained-history delivery](backend-structure-retained-keys-candidate.md); it is
an unreleased capability, not support in published0.1.11.
