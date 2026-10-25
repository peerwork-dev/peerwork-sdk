# Explicit PUBLIC publication — unreleased candidate

The matching candidate service advertises `owner-selected-publication-v1`.
This document describes source and isolated qualification, not a production
endpoint or published SDK version. Local development packages still use the
0.1.11 development version and must not replace published 0.1.11 artifacts.

## Disclosure and authority

This is the optional Owner-curated publication path. The source candidate also implements member-authored atomic PUBLIC business actions under an explicit Owner policy; see [member-authored PUBLIC actions](backend-structure-public-actions-candidate.md). This removes the need for Owner republishing for each contribution. Selected converted records preserve Owner-attested historical author/time separately from the conversion signer. Broader all-workspace migration remains release work.

A workspace remains PRIVATE by default. An Owner can publish a named public
view and selected immutable record snapshots. This does not grant anonymous
membership, expose all service-readable structure, publish a protocol manifest,
or deliver content keys. PRIVATE access and PUBLIC publication are independent.

`structure.publication.set` creates, updates or withdraws the public view. It
requires the Owner, an expected workspace revision, an expected publication
revision and `disclosure: "PUBLISH_SELECTED_CONTENT"`. The initial publication
revision is zero. Publication titles and descriptions are selected public text;
they need not disclose a private workspace's name.

`structure.publication.entry.set` publishes one exact source record. Its scope
selects the workspace, instance and protocol. Its body binds the exact record
ID/revision, original actor, creation time, source-intent digest and readable
structure, plus the selected public title and text. The service verifies the
source fields against the indexed record and accepts only the workspace Owner.
Source selection never copies another record from the original multi-record
command into the public response.

The publisher explicitly attests the public body. The backend has no PRIVATE
body keys and cannot prove that this text equals the original private plaintext.
The public page distinguishes the source author/time from the publisher; it
does not call the public text a new signature by the original author. Publishing
never needs a private key export or full-history replay.

## SDK publication

The service additionally advertises `selected-publication-snapshot-v1` for the
native selected-record producer. First create an explicitly public view with
`structure.publication.set`. Publishing a record does not create that view.

```javascript
const publication = await owner.publishSelectedRecord(workspaceId, {
  instance_id: instanceId,
  protocol_digest: protocolDigest,
  record_id: recordId,
  revision: recordRevision,
  idempotency_key: 'release-note-2026-10-24',
  title: 'Release notes',
  disclosure: 'PUBLISH_SELECTED_CONTENT',
  body: {from: 'RECORD'},
});
```

Here `owner` is a selected Node Context; a Kernel client accepts the same
selection including `workspace_id`. Python exposes `publish_selected_record`
and `publish_selected_record_async` on both clients. CLI accepts the Kernel
selection JSON file with `kernel publish-record ORIGIN JOURNAL IDENTITY FILE`.
Context returns structure under `result`; Kernel/CLI return `result.structure`.

`body: {from: 'RECORD'}` publishes the verified selected body's decrypted text.
Missing keys or invalid ciphertext fail explicitly. `body: {from: 'TEXT', text:
publicText}` publishes the Owner's chosen public summary and does not require
access to private body keys. Neither mode publishes private commands or keys.
The SDK obtains exact structure, source fields and the selected publication
revision with one indexed `structure.publication.prepare.get` read. Set
`expected_publication_revision` to require a particular revision; omission uses
the observed selected entry revision once. A signed packet is never rebased.

Before preparation, the native SDK encrypts an immutable local plan keyed by
actor, origin, workspace and idempotency key. A repeated call returns an already
accepted outcome before repeating prerequisites. Unknown outcomes resume the
saved signed packet; interrupted preparation resumes by the original command
ID. Changed input conflicts. Preparation, submission and recovery share the
native 30-second asynchronous call budget; a pending result carries the durable
continuation rather than requiring an Agent to reconstruct publication fields.
A verification failure during preparation preserves the original operation ID,
reports `PREPARATION` / `NOT_SUBMITTED`, and disables automatic retries. Resolve
the evidence or source issue before resuming that operation. Reads and publication
do not replay history.

Converted records include `source.attribution` in the Owner-signed public
intent: `OWNER_ATTESTED_CONVERSION`, historical `actor_id`, `created_at` and the
exact `legacy_source`. Unknown historical author/time are null. The conversion
signer remains `source.actor_id`; the UI labels historical attribution as the
Owner's attestation, not a fresh historical-author signature. Changelog readers
expose the historical author/time plus `source_signer_actor_id` and
`attribution_assurance` so consumers can retain this distinction.

The lower-level `structure.publication.entry.set` remains available for callers
that already hold a verified exact record. Its converted attribution must match
the checkpoint provenance. Offline helpers `publicationBody(text)` and
`publication_body(text)` encode at most65,536 UTF-8 bytes. Both high-level and
raw publication require explicit disclosure; PRIVATE remains the default.

## Anonymous reading and withdrawal

`GET /api/workspace/v1/structure/public` accepts `kind`, a fresh random43-character
`nonce`, and the selected fields:

| kind | Selected fields | Result |
| --- | --- | --- |
| `CATALOG` | optional cursor, limit | Active public views |
| `WORKSPACE` | workspace_id | Public title, description and Owner publication |
| `ENTRIES` | workspace_id, optional instance_id, cursor, limit | Published entry page |
| `ENTRY` | workspace_id, record_id, optional instance_id | Exact published entry |

Duplicate or undeclared query parameters are refused. Limits are1–32, default20.
The optional `order` is `RECORD_ID_ASC` by default; `PUBLISHED_DESC` uses the indexed publication time and record ID in descending order. Changelog reads use `PUBLISHED_DESC` to obtain the latest page directly. No offset or total-count scan is performed.

Keyset cursors bind the service signature, view, kind, order and instance filter; a
withdrawn/reopened or edited containing view invalidates its earlier entry
cursors. Entry pagination is live keyset pagination, not a retained snapshot.

Responses carry a `peerwork.publication-read.v1+jws` receipt binding the audience,
nonce, submitted decoded query fields and result digest, plus the original selected Owner
publication intents. The query digest covers the actual decoded string map (including numeric strings as submitted), omitting absent/null fields. Clients do not reproduce server-filled schema defaults, so a future optional query parameter does not change receipt verification for an unchanged request. The frontend verifies both layers and the selected Owner
before rendering. Payload and proof byte budgets reduce page size;32maximum
bodies are not loaded eagerly. PUBLIC reads persist no commands or identities.

The DBless frontend serves the public view at the canonical workspace, instance
and record URLs. PUBLIC content is rendered on the server and works without
JavaScript. `?access=private` explicitly opens device authorization for the
PRIVATE workspace behind the published view. The homepage combines opening a
shared workspace with the public directory. Body text is escaped and large list
previews link to the complete selected entry.

An Owner withdraws one entry by submitting `structure.publication.entry.set`
with `state: "WITHDRAWN"`, `record_id`, and the current
`expected_publication_revision`, in its exact instance/protocol scope. No public
text is needed in a withdrawal. Exact anonymous reads then return404 and the
entry leaves public pages. Withdrawing the containing view hides all its
entries. Authorized source history remains intact; previously copied public
text cannot be recalled or erased from third parties.

## Anonymous SDK and Changelog readers

```javascript
const reader = new peerwork.PublicationReader({
  controlOrigin, browserOrigin, workspaceId, ownerActorId, ownerKeyId,
  audience: expectedAudience, serviceKey: expectedServicePublicKey,
});
const first = await reader.list({instanceId, limit:20, order:'PUBLISHED_DESC'});
if (first.result.next_cursor) {
  const next = await reader.list({instanceId, limit:20,
    order:'PUBLISHED_DESC', cursor:first.result.next_cursor});
}
const selected = await reader.get(recordId, {instanceId});
```

```python
reader = peerwork.PublicationReader(
    control_origin=control_origin, browser_origin=browser_origin,
    workspace_id=workspace_id, owner_actor_id=owner_actor_id,
    owner_key_id=owner_public_key, audience=expected_audience,
    service_key=expected_service_public_key,
)
first = await reader.list_async(instance_id=instance_id, limit=20,
                                order="PUBLISHED_DESC")
selected = await reader.get_async(record_id, instance_id=instance_id)
```

```sh
peerwork publication read --source public-source.json --kind ENTRIES --limit 20 --order PUBLISHED_DESC
peerwork publication read --source public-source.json --kind ENTRY --record RECORD_ID
peerwork changelog read --source changelog-source.json --limit 20
```

Generic source files use the snake_case names in the Python example; all keys
are public signing keys, never seeds. Changelog sources use the existing official
source shape from `changelog source`, or an explicitly selected custom source,
including its instance ID. `ChangelogClient.read`/`read_async` accept `limit`,
`cursor` and `checkpoint`, and return `entries`, `next_cursor`, attribution,
qualified browser URLs and a new-profile checkpoint. `offset`, total entry
counts and journal replay are unsupported. The official source is pinned, but
its production workspace still needs the new-profile conversion/publication
before the candidate reader can serve it.

These readers create no identity, profile or SQLite state. One entry-page call
makes discovery plus two selected GETs: current publication metadata and the
page. An exact workspace call makes discovery and one metadata GET. A selected
result verifies fresh nonce receipts and original Owner intents, not the entire
history. The native driver has a30-second operation budget and bounded responses.

The reader's in-memory checkpoint pins the service and observed public-view
revision. Explicit checkpoints can be passed between invocations. A freshly
service-signed older view is refused after a newer view was observed. This is
local continuity plus service-selected freshness, not an independent proof of
the globally latest entry or historical rule execution.

Errors carry a phase, retryability and recovery action. A changed view/cursor
requires a fresh page. Missing publication is a definite error, not an empty
successful result. Missing capability returns `CAPABILITY_UNAVAILABLE` before
any selected read or durable operation. Owner/signature/pin failures do not
silently retry through a legacy endpoint.

## Deployment and remaining delivery

Schema6 adds publication tables and schema7 adds newest-first indexes; schema8
also supports retained key delivery. Explicit upgrades from5 and6 preserve
private commands, identities, memberships and keys. Normal startup
never migrates implicitly. Private modes and retired routes are not re-enabled.

The frontend `public` role uses `WORKSPACE_CONTROL_ORIGIN`. Set
`WORKSPACE_RECEIPT_PUBLIC_KEY` and `WORKSPACE_AUDIENCE` to pin the qualified
service identity. This role needs no PostgreSQL access or service private key.
`WORKSPACE_INTERNAL_CONTROL_ORIGIN` optionally supplies a separate fixed SSR
transport such as `http://control:8080`. It requires both the service public-key
and audience pins; the browser keeps `WORKSPACE_CONTROL_ORIGIN` and never sees
the internal address. Internal failure is visible, with no public-origin
fallback. Without an explicit public-key pin and without this internal binding,
first discovery trusts the configured origin;
this is not an independent authenticity guarantee. Public content failure is
visible, and does not render a false empty workspace.

Native anonymous Node/Python/CLI reading, Changelog pagination and high-level
selected-record publication have isolated installed-package qualification. Broader
real PUBLIC conversion, final deployment/recovery qualification, portable SDK
release and official public Changelog publication remain release work.
