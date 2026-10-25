# Browser access — unreleased candidate

This is source and local qualification work. It does not announce a deployed
service, published SDK release or finished PUBLIC workflow. The matching service
advertises `browser-structure-access-v1`, `owner-pinned-browser-access-v1`
and `owner-approved-key-floor-v1` in addition to the current structure,
access and body-key capabilities. Local development packages still carry a
0.1.11 development version; they must not replace published 0.1.11 artifacts.

## Open and approve

The canonical URL is `/workspaces/WORKSPACE_ID`. `/w/WORKSPACE_ID` and the earlier
`/private/workspaces/WORKSPACE_ID` HTML routes redirect there. Instance and record
links preserve their selection. SDK URL generation now uses the canonical route and adds `?access=private` for PRIVATE links. Record links require instance ID and a positive record revision, instead of emitting an unqualified record path. It returns the current commands/context/public-read endpoints and never a retired journal locator. The retired legacy APIs remain HTTP410; these
HTML aliases do not re-enable an old protocol or reader. The earlier PRIVATE prefix preserves private access by redirecting with `access=private`, including when a public view exists.

The browser generates its own signing and encryption keys and displays a signed
request to copy into an existing Agent conversation. The Owner approves that
request with an already selected SDK Context:

```javascript
// owner already selects the expected service, identity and workspace.
const approval = await owner.authorizeAccess(workspaceId, {
  request_jws: packet.request_jws,
  ttl_ms: 24 * 60 * 60 * 1000,
  follow_current_key: true,
});
```

```python
approval = await owner.authorize_access_async(workspace_id, {
    "request_jws": packet["request_jws"],
    "ttl_ms": 24 * 60 * 60 * 1000,
    "follow_current_key": True,
})
```

Treat the packet's origin and workspace as assertions to check against the
configured Context and the user's intended workspace. Do not silently construct
a new trusted Context from an arbitrary received packet. Request signatures
prove device-key possession, not the provenance of a conversation or user intent.

Return `approval.browser_approval_reference` from the verified SDK result to
the user. On the first visit, the user pastes it into Owner approval reference
and selects Connect this browser. The reference binds the workspace, browser
request, Owner identity, original accepted command and its signed-intent digest.
The committed Owner intent also signs the observed body-key epoch; the browser
uses it as a minimum on its first read, before it has any local epoch history.
It contains no secret and is not a short-lived bearer code. The browser reads
only its own current approval, checks the original Owner signature and request,
and pins that Owner identity before opening any content or encrypting a write.
The API alone cannot select the first trusted Owner.

On later visits, a matching confirmed Owner can resume automatically. A new
request nonce is saved locally; approval of that exact request is verified and
its signed key floor applied before an approval renewal is used. An older
admission is not silently substituted for a requested new one. The browser
polls for approval and offers Check approval. No Agent identity transfer is
required. An invalid reference keeps the entered value and shows a visible error,
rather than clearing the field. The original accepted approval remains checkable
while its current session is active even after the ten-minute request window. Signing and recipient private keys are
non-extractable CryptoKeys stored in this browser's IndexedDB. HPKE uses the
existing public/private key pair without exporting its private half. The Agent's
Owner identity stays in its selected client profile.

Access defaults to read-only. A separate browser request names one manifest
action; the Owner must explicitly supply the matching `selected_write` to grant
it. Session renewal creates a new membership generation and does not implicitly
preserve other write grants.

## Body access and historical keys

An ordinary approval delivers the current body key. `follow_current_key: true`
explicitly authorizes subsequent current-key deliveries while the approved
membership and recipient certificate remain valid. The Owner-side coordinator
performs rotation and encrypted distribution; the backend never receives body
keys. See [key lifecycle](backend-structure-content-keys-candidate.md).

A current-key grant does not authorize historical epochs. The Owner can choose
additional retained keys with `key_ids`, within the existing32-key approval
bound. The browser fetches only missing keys needed by the selected page,
validates the original Owner grants and imports verified non-extractable AES
keys. Readable structure remains visible when a body key is unavailable, with
an explicit per-body message. It is not shown as an empty workspace.

Automatic historical-key selection and larger historical handoff jobs still
need work. The browser tests' explicit selected historical-key approval is not
proof that the default approval grants all retained history. Do not ask users
to rebuild identity or replay history to obtain keys.

## Bounded reads and trust

The workspace view starts with a selected instance page. Instance links use
`structure.instance.resolve`, an exact workspace-authorized lookup returning the
selected digest and manifest without traversing the instance catalogue. Record
pages and exact record/revision views verify fresh service receipts and the
original author signatures. The browser performs no journal/history download or
local business-state reconstruction.

Structure has `BACKEND_CURRENT_STATE` assurance. A successfully opened body has
original signing-author and AEAD assurance; this does not independently prove
business-rule execution. Owner-attested conversions preserve their separately
attested original author/time and identify the conversion signer rather than
impersonating the historical author.

Key continuity pins reject an older Owner-signed epoch after a newer epoch was
observed. This is a local continuity guarantee, not an independent global
freshness service. Body keys are indexed by selected service/workspace/key;
plaintext bodies are neither saved in the read cache nor written to the local
pending journal. Body transport supports64KiB per body and per action in total.

Requests and authorization use nonce-bound service-signed time. Browser wall
clock is not an authorization input. The human request lasts10minutes; the
Owner chooses the access session lifetime, default24hours and maximum31days.

## Writes, recovery and ending access

The selected action form separates readable action fields from its optional
private body. The browser encrypts locally, saves one immutable signed request
before submission and keeps it across browser restarts. Transient reply loss is
reconciled by original operation ID. Unknown outcomes remain pending; retry does
not silently rebase revisions or create another business operation. A pending
action must be reconciled before another action is prepared.

End browser access signs `structure.access.end` for this device's current
membership generation. It revokes that session remotely and fences the current
body-key epoch in the same transaction. It cannot revoke the Owner or another
member. New reads fail after the end commits, and later body writes require
Owner-side key rotation. Structure-only actions remain independently available.
Previously obtained keys or plaintext cannot be erased retroactively.

The page checks membership while open without periodically rebuilding the
visible record page or discarding a draft. Authorization or verification failure
locks the view. With JavaScript disabled, the HTML shell contains no private
workspace data and explains the SDK/CLI alternative.

## Deployment boundary

The frontend can run with `WORKSPACE_ROLE=public` and
`WORKSPACE_CONTROL_ORIGIN=https://api.example.test`, without PostgreSQL access
or a platform signing key. Set Control's `WORKSPACE_PUBLIC_ORIGIN` to the exact
frontend origin for CORS. Both roles use the same image's owned browser assets.
Frontend health fails when its entry asset is absent. The frontend also has an explicit [PUBLIC publication](backend-structure-publication-candidate.md) path with verified anonymous reads and server-rendered no-JS content. Public publication does not expose a PRIVATE workspace wholesale. Native anonymous SDK/Changelog readers now have installed-package qualification; official workspace conversion and release remain pending.

Production cutover, broader converted-workspace/member continuity, portable SDK
publication and the official public Changelog remain release work.

## Reading retained history

When authorizing an existing workspace's browser reader, an Owner can select
`include_history: true` to grant published key epochs through the observed head.
The SDK delivers bounded historical batches and reports `key_history` readiness;
the Agent does not enumerate the first page's key IDs. The default remains
current-key-only, while `follow_current_key` independently controls future keys.
The browser verifies the Owner's historical envelope and imports non-extractable
keys for the selected bodies without resetting its current-head floor. See
[retained-history delivery](backend-structure-retained-keys-candidate.md).
