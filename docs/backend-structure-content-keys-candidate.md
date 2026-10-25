# Canonical body-key epochs — unreleased candidate

This document describes source and local development packages, not a published
SDK or deployed production capability. It extends the candidate
[access workflow](backend-structure-access-candidate.md).

## Model

The service stores an Owner-signed current key commitment, epoch and provenance.
It never receives the body key. Every new encrypted-body write must use that
current, usable key. Structure-only business actions do not depend on body keys.

An Owner selects an epoch with `structure.content-key.set`, using `key_id`,
`expected_epoch` and `expected_head_revision`. First publication expects epoch
zero and a null revision. The service increments the epoch, rejects reused key
IDs and preserves the original accepted command for reconciliation. A pure
`structure.content-key.get` or `structure.workspace.get` returns the current
commitment with its original Owner signature.

Revoking a workspace member invalidates the current key in the same transaction.
Body writers hold a shared lock on that selected key-head row until their
transaction finishes. Rotation and revocation acquire its exclusive lock, so
an admitted old-key writer finishes before rotation, and later old-key writes
are rejected. Independent structure actions do not acquire this key lock.

Granting the current key to a finite session sets a conservative earliest
`rotate_before` deadline. At that deadline the epoch cannot encrypt new bodies.
This exposure is tracked by workspace, epoch and actor: replacing a membership or shortening its session still shortens the deadline even when no key is delivered again. Renewal cannot extend that key's existing exposure window. The service checks
the deadline again after action execution and rolls back effects if it elapsed.
Old ciphertext and authorized retained decryption keys remain intact.

## SDK operation

For a new plaintext-body operation, the native SDK reads selected current
metadata, verifies the Owner signature and epoch, selects the retained key or
fetches its exact recipient-bound delivery. It does not read journal history or
all workspace members. Resuming a saved body operation preserves its original
ciphertext and command ID; it never silently re-encrypts that intent.

The first Owner body write or key approval initializes the current commitment
if none exists. Lost initialization replies are reconciled with an indexed
read of the original operation. If that observation is also unavailable,
`PREREQUISITE_PENDING` includes the saved command and workspace IDs. Context
errors supply a recovery continuation instead of losing that operation.

### Automatic Owner prerequisite

When an Owner submits a new plaintext-body action or a key-bearing access
approval, the SDK automatically repairs an expired/revoked current head. It
publishes one durable crypto selection, confirms the authenticated head, then
continues the original parent operation. It does not update the business
instance revision or replace the caller's expected revision. A stale business
CAS remains a verified business refusal even when crypto maintenance succeeded.

If publication committed but all replies and indexed observations are lost,
the pending result names the saved business parent in `PREPARATION`, with
`effect_certainty: NOT_SUBMITTED`. Resuming that parent reconciles the original
crypto child before encrypting/submitting the business packet. The same input
and ID never produce another body record or blindly repeat the rotation.
A direct command-ID resume of an existing signed packet uses that packet first;
it does not require re-reading the earlier preparation plan.

Ordinary members cannot acquire Owner maintenance authority through this path.
They still need the Owner runtime to maintain the workspace. The service never
holds the body key or performs this cryptographic work itself.

Publishing the head and delivering its key to every authorized recipient are
independent. An Owner business write does not wait for full recipient fanout.
Its verified acceptance does not claim that other devices can already open the
body. A pending backend delivery job retains the original publication and
cursor, and the native Owner worker continues it:

```sh
# worker.json: {"workspace_id":"WORKSPACE_ID"}
peerwork kernel coordinate-content-keys "$ORIGIN" "$JOURNAL" "$IDENTITY" worker.json --watch
```

This selects one explicit Owner profile and workspace. Keep the process running
as part of that Owner's client runtime. It handles bounded recipient pages and
saved outcomes; an Agent does not enumerate recipients or write a coordination
loop. Existing `follow_current_key` consent, membership generation, expiry and
recipient proofs remain mandatory. Worker downtime can delay device readiness,
but it does not turn an already accepted Owner business action into a failure.

The default access approval remains current-key-only. Automatic repair does not
authorize all historical keys, create future-key consent, renew a revoked member
or bypass a certificate/session deadline.

### Explicit rotation

Explicit Owner rotation is one SDK call:

```javascript
const result = await context.rotateContentKey(workspaceId, {
  idempotency_key: 'revoke-device-2026-10-24'
});
```

```python
result = await context.rotate_content_key_async(workspace_id, {
    "idempotency_key": "revoke-device-2026-10-24"
})
```

The advanced Kernel facades provide `rotateContentKey` / `rotate_content_key`
with `workspace_id` in the selection. The CLI accepts the same JSON selection:

```sh
peerwork kernel rotate-content-key ORIGIN JOURNAL IDENTITY rotation.json
```

The native runtime retains a random candidate in protected local storage before
submitting its signed selection. It selects that key only after publication is
verified or a fresh authenticated head confirms it. Repeating an idempotency
key reconciles the original command; it does not generate another epoch. A late
retry of an older accepted rotation does not reset a newer local selection.

Protected, origin/identity/workspace-scoped metadata pins observed Owner and
epoch continuity. Older epochs, a missing previously observed head, conflicting
key/provenance for the same epoch, or a changed Owner fail with
`CONTENT_KEY_ROLLBACK`. This detects rollback after this identity has observed
a newer head; it does not establish independent global freshness on a new device.
The local metadata addition preserves existing keys and selection without
identity migration or receipt replay.

## Explicit authority for future epochs

An access approval grants only the selected current or historical keys by default.
Set `follow_current_key: true` on an Owner approval to authorize deliveries of
future current keys to that request's certified recipient, while the selected
membership generation and certificate remain valid:

```javascript
await owner.authorizeAccess(workspaceId, {
  request_jws: request.result.request_jws,
  ttl_ms: 24 * 60 * 60 * 1000,
  follow_current_key: true,
});
```

This requires a content-key grant. Structure-only approval cannot silently grant
future body access. A renewed SESSION selects a fresh membership generation;
future-key authority must be explicitly approved for that generation. A
`KEYS_ONLY` approval can authorize another certified device for an existing
session without renewing membership. Following current keys does not grant all
historical keys or extend a certificate or session.

## SDK-owned distribution and interruption recovery

The high-level rotation call completes only after both publication and its
backend delivery job are verified complete. The SDK reads bounded current-member
and certified-recipient pages, verifies each original Owner approval, encrypts
recipient-bound boxes locally, signs the batch and advances a persisted backend
cursor. Each batch contains at most 32 recipients and has a separate proof-byte
budget. Recipient metadata and exposure updates use indexed aggregate SQL.
No business-history replay is involved. Group rotation necessarily scales with
the number of currently authorized recipients; this is not constant-time group
key exchange.

If a recipient's membership or approval changes before submission, the entire
batch receives a signed no-effect refusal. The SDK obtains a fresh page under a
new internal operation ID; the rejected encrypted boxes are never published in
a successful event. Unknown transport outcomes retain the exact original packet
and are reconciled before another stage is prepared.

The delivery driver has a 30-second budget and a bounded step count. A larger
job or unavailable transport can return pending progress with `phase:
'KEY_DELIVERY'`. Publication is already committed in this phase. Repeat the
same rotation selection or use its Context continuation to finish distribution;
recovering only the publication command does not finish the group operation.
Never change the caller's idempotency key merely because a response was lost.
A later epoch can supersede an unfinished job; it returns an explicit blocked
state rather than silently repeating the old rotation against a new epoch.

An Owner process can also coordinate the current workspace without the business
Agent inspecting pages or certificates:

```javascript
await owner.coordinateContentKeys(workspaceId);
```

Python provides `coordinate_content_keys` and
`coordinate_content_keys_async`; advanced Kernel selections contain
`workspace_id`. The CLI can perform one coordination pass or keep watching:

```sh
peerwork kernel coordinate-content-keys ORIGIN JOURNAL IDENTITY workspace.json
peerwork kernel coordinate-content-keys ORIGIN JOURNAL IDENTITY workspace.json --watch
```

`workspace.json` contains `{"workspace_id":"..."}`. Watch polls every five
seconds, rotates an unusable current epoch and resumes its delivery job. It
prints status metadata only. Keep the same protected identity, journal and local
key cache across restarts. A saved stage survives process termination; a restart
reconciles that stage before advancing. Use normal process supervision for a
persistent coordinator. This process holds Owner authority and key access on
the Owner side; the backend still never holds plaintext body keys.

## Availability and remaining work

Rotation and encryption require an online Owner-side client. Automatic
recipient distribution and a restartable Owner coordinator are implemented and
qualified in local installed-package tests. They are not deployed or published.
Until an Owner client performs rotation after revocation or expiry, new
encrypted bodies fail explicitly; structure-only actions remain available.
Run the coordinator when unattended key availability is needed. There is no
promise that merely approving access starts a background process.

The matching service advertises `canonical-content-key-epochs-v1` and
`owner-current-key-delivery-v1`. The high-level SDK checks both before preparing
a rotation or distribution mutation. Missing capabilities fail before any
submission or pending operation is created. This is a capability check, not a
claim about a published minimum SDK version.

The additive backend metadata upgrade preserves earlier signed records but
marks pre-exposure-tracking key heads unusable. An explicit Owner rotation is
required before new body writes; the service does not guess earlier exposure or
scan old history to infer future-key authority. Existing retained keys and
ciphertext remain unchanged.

Retained history is not re-encrypted, and revocation cannot erase keys or
plaintext a former member already obtained. The [body attachment limit](structure-body-content-candidate.md) is now
64 KiB per body and per action in total. The [browser candidate](backend-structure-browser-candidate.md) now opens selected encrypted pages and imports rotated keys in real Chromium. Automatic historical-key handoff, larger-file transport, PUBLIC workflows, broader migration continuity and production/release qualification remain separate work.

## Explicit retained-history range

The source candidate supports `include_history: true` on an Owner approval. It
signs the observed epoch ceiling and uses a separate persistent job with native
HPKE batches of at most32 keys. The default remains current-key-only; future-key
consent stays independent. See [retained-history delivery](backend-structure-retained-keys-candidate.md)
for readiness, recovery, source-version requirements and Owner runtime state.
