# Bounded local pending requests

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

The local transport journal retains exact signed mutation requests so a lost
reply can be reconciled under the same command ID. A pending entry means only
that this journal has no verified acceptance response. The service may already
have committed it. Listing never retries a request.

## Selected reads and pagination

Node `kernel.pendingPage({after?, limit?})`, Python
`kernel.pending_page(after=None, limit=32)` (also `pending_page_async`) and
CLI `kernel pending-page ORIGIN JOURNAL IDENTITY OPTIONS_JSON_FILE` return:

```json
{"items":[],"next_after":null,"consistency":"LIVE_KEYSET"}
```

Limits are 1–32. Pass a non-null `next_after` as the next `after` with the same
origin, journal and identity. Ordering is by command ID. This is a live view:
accepted entries disappear, and concurrent new entries before a cursor appear
on a new traversal. It is not a historical snapshot or a history audit.

Each page uses the `(local_key_id, command_id)` index and selected command
primary-key lookups, then verifies at most 32 original signed requests under
the selected identity and pinned discovery. Completed history and other
identities' pending rows are not enumerated or verified. Cost is bounded by
`O(log N + k)`, with bounded packet sizes and `k <= 32`. Local pending reads
use the existing discovery pin and make no network requests. They make no
freshness claim about remote status.

The compatibility `pending()` method returns one complete list when there are
at most 32 entries. Larger lists return `PENDING_PAGE_REQUIRED`, never a silent
partial result. Use the paged interface for larger lists. Selected `status`,
submission and recovery retain their original proof checks.

## Existing local journals

The additive native v4 → v5 schema upgrade creates an empty locator and stores
one primary-key endpoint for legacy history. Ordinary open never backfills or
audits all historical rows. New requests and acceptance removals maintain the
locator in the same SQLite transaction as their authoritative journal writes.
The locator is not a substitute for signature or acceptance proof.

The same bounded maintenance also creates an accepted catalog-BEGIN locator.
Uploading or inspecting a chunk selects its BEGIN by identity and upload ID,
then verifies that exact author's request and accepted service reply. It no
longer scans unrelated saved commands. Ambiguous accepted BEGIN sources are
rejected instead of choosing one. A legacy catalog-chunk lookup may therefore
also return `PENDING_INDEX_BUILD_REQUIRED` until explicit locator construction
is complete; ordinary structure-intent selected recovery does not require it.

Before legacy locator construction is complete, pending queries return
`PENDING_INDEX_BUILD_REQUIRED`. Selected operations remain available. Call:

- Node: `await kernel.buildPendingIndex()`.
- Python: `kernel.build_pending_index()` or its async counterpart.
- CLI: `kernel build-pending-index ORIGIN JOURNAL IDENTITY`.

One call drives at most 64 transactions of at most 32 historical rows, with a
two-second soft work budget checked between transactions. SQLite lock waits
remain subject to its five-second busy timeout. The result contains
`complete` and this invocation's `scanned_rows`; it does not count all history.
If incomplete, invoke the same method again. Restart resumes its durable
checkpoint; no external cursor, old profile, identity transfer or server retry
is required. Locator entries and checkpoint advancement commit together.
Concurrent new writes are covered even if they sort behind that checkpoint.

This explicit one-time maintenance may visit the retained local history. It
does not verify or declare all historical acceptances, send requests, rebuild
workspace state, or change original packets, receipts or identities. Malformed
unclassifiable pending packets remain retained and cause a state error rather
than silently disappearing. An explicit full audit remains a separate task.

## Backend operation discovery

An admitted backend task can be discovered and followed from another local
journal without copying this outbox. See
[backend operation discovery](backend-operation-discovery-candidate.md).
Use that interface for remote maintenance progress; use this local locator for
requests whose service outcome is not yet confirmed here.
