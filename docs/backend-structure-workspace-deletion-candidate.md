# Workspace deletion — source candidate

This capability is implemented and under local qualification. This document does
not establish production availability or a released SDK version. Require
`durable-workspace-deletion-v1` in discovery; legacy deletion endpoints remain
retired. The supported execution profile is `backend-structure-v1`.

## Submit once and wait

```js
const current = await kernel.executeStructureIntent({
  action: 'structure.workspace.get', workspace_id: workspaceId, body: {}
});
const outcome = await kernel.executeStructureIntent({
  action: 'structure.workspace.delete',
  workspace_id: workspaceId,
  expected_workspace_revision: current.result.structure.workspace_revision,
  idempotency_key: 'delete-this-workspace-once',
  body: {confirm_workspace_id: workspaceId}
});
```

Only the active Owner may authorize deletion. Both the target confirmation and
workspace revision are mandatory. A stale revision is a definite refusal;
there is no implicit rebase or automatic authorization of a different target.
Python's sync/async `execute_structure_intent`, CLI `kernel intent`, and a
selected Context use the same native execution path.

Admission drains existing writers under a workspace-local fence, closes online
access and PUBLIC visibility, and records one irrevocable Owner authorization.
Subsequent ordinary writers share that fence with each other; they do not take
an exclusive workspace lock. Other workspaces continue independently.

An independent backend worker removes related data in bounded transactions of
at most32 selected purge units plus bounded accounting/recovery metadata. Large
record, publication and command payloads also obey a1MiB batch budget, using
selected indexes and indexed foreign-key checks. It owns
the cursor, fairness and storage-failure backoff. The SDK does not page records,
replay history, maintain an Owner listener, or keep resubmitting authorization.

The native call observes signed progress within its existing30-second total
budget. `COMPLETED` means the backend reports `APPLIED`/`DONE`, verified against
the original Owner intent. The original admission receipt is immutable and is
only `ORDERED`; admission alone is not completion. A wait timeout or cancellation
returns `PENDING` with the original command ID and `DELETION` phase. Cancelling
waiting does not cancel the accepted deletion.

## Resume and discover

Use `resumeStructureIntent(originalCommandId)`, Python
`resume_structure_intent`, or the corresponding CLI resume command to continue
observing the existing job. A Context uses `recover(workspaceId, {commandId})`.
The same operation ID still works after workspace membership and command rows
have been removed. Repeating the original idempotency key recovers its original
receipt; a newly identified deletion against that workspace is refused.

An Owner with a fresh local journal can discover their tasks without an active
workspace membership:

```js
const jobs = await kernel.executeStructureIntent({
  action: 'structure.workspace.deletions.read',
  body: {view: 'OPEN', limit: 16, cursor: null}
});
// HISTORY includes completed tasks. Follow next_cursor for another bounded page.
```

Each entry includes the source Owner signature, original command ID and current
service-signed progress. Cursors bind the Owner and query. Another identity
cannot list or read the Owner's jobs. Pure registry reads require only the
selected self-certifying identity and never enroll a new root or allocate a
mutation slot; an existing revoked identity remains denied.

A fresh selected Context can wait without the original transport journal:

```js
await context.followOperation(workspaceId, {
  kind: 'WORKSPACE_DELETE', command_id: originalCommandId
});
```

Python exposes the same selection through `follow_operation` and its async
variant. This follows service progress without importing or resubmitting the
original deletion. A direct `structure.workspace.deletion.get` query with
`body: {command_id: originalCommandId}` returns one current observation.

Corrupted authorization or admission evidence stops disposal and reports
`VERIFICATION_BLOCKED`. SDK waiting returns a non-retryable verification failure
and identifies the original operation. It never labels that condition completed
or generates another deletion. Storage failures retain the committed cursor;
backend retries do not restart deletion from the beginning.

## What is removed

Deletion removes online workspace records and history, commands/events,
instances/protocol definitions, memberships, selected grants and role claims,
body-key metadata and grants, current and retained key-delivery jobs,
withdrawal markers, all projection generations and maintenance jobs, PUBLIC
policies/entries/views, conversion progress and workspace accounting. Capacity
and the Owner's workspace count are released after cleanup completes.

A compact recovery registry retains only deletion authorization/receipt and
progress metadata. It contains no workspace name, record body or body key.
Resource aliases become non-reusable tombstones without their resource or
workspace target. Retired creation command hashes prevent a purged original
creation packet from creating another workspace on retry. The Owner identity
and unrelated workspaces are preserved. Rejected post-delete requests cannot
recreate rows in the deleted workspace.

This deletes authoritative online rows; it is not cryptographic erasure of
PostgreSQL WAL, offline conversion archives, retained backups, SDK caches or
independent copies. Progress states explicitly report `backups: NOT_TRACKED`
and `independent_copies: NOT_RECALLABLE`. These copies follow their separate
retention policies. There is no cancel/undo after deletion admission; recovery
from removed business data requires a separately authorized backup restore.

## Schema and availability

The explicit PostgreSQL10-to11 migration adds the deletion registry, its indexes,
selected purge indexes and referencing-column indexes. It preserves existing
records, signatures, identity and ciphertext. A full structural audit reports
`POSTGRES_AUDIT_DELETION_IN_PROGRESS` while an irreversible cleanup is incomplete;
it does not misreport intentionally partial cleanup as a verified full workspace.

Exact production service and SDK versions will be announced with the release.
Local development0.1.11 package filenames must not replace published0.1.11.
