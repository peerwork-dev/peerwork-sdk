# Backend maintenance (unreleased candidate)

This describes modified SDK and backend source. These capabilities are not in
the published 0.1.11 packages or a deployed production release. The first job
type is `CURRENT_RECORDS`, a derived current-record index rebuild. It does not
convert legacy PRIVATE history or authorize a business-record transformation.

## One call, backend-owned execution

```javascript
const selected = await context.describe(workspaceId, {
  instanceId,
  protocolDigest,
});
const outcome = await context.operate(workspaceId, {
  kind: 'structure.intent',
  request: {
    action: 'structure.maintenance.rebuild',
    instance_id: instanceId,
    protocol_digest: protocolDigest,
    expected_instance_revision: selected.result.revision,
    body: {
      expected_event_revision: selected.result.event_revision,
      ttl_ms: 60000,
    },
  },
}, 'repair-current-index-42');
```

Only an Owner can start or cancel this maintenance. The immutable signed intent
binds the workspace, instance, protocol, current source revisions and bounded
job lifetime. It authorizes that specific derived rebuild, not future arbitrary
actions. TTL is between 1 and 600 seconds, measured by backend transaction time.
The default is 60 seconds.

The backend persists the job, candidate generation, cursor, evidence digest and
progress in the same Control database. Its server scheduler advances work after
caller disconnects and process restarts. The SDK verifies admission and waits
for signed progress. It does not send source pages or reconstruct a workspace.

`operate` returns `status: 'verified'`, `'rejected'` or `'blocked'` after a final
observation. It includes the original `command_id` and a separate
`observation_command_id`. The low-level Kernel interface returns
`state: 'COMPLETED'`, the original `command_id`, and `result` containing the
verified observation. Its result command ID remains the actual read command ID;
the SDK never rewrites a read receipt to impersonate the original mutation.

An immutable admission receipt remains `ORDERED` permanently. Completion is a
separate signed observation, checked against the original job and source pins.
If the bounded 30-second driver wait ends first, the call returns `IN_PROGRESS`
with the original operation ID and `MAINTENANCE` phase. Resume the original ID;
the backend continues independently. Cancelling a client wait does not cancel
the backend job. Explicit Owner cancellation uses
`structure.maintenance.cancel` with the job ID.

## Current registers, not historical replay

The backend maintains each entity's current structural pointer in the same
transaction that admits a record or changes its selected head. This register
also covers standalone and implicit-head records. Historical unselected
versions do not appear in it.

The serving record index is a separate generation selected by one per-instance
pointer. A rebuild reads only the current register and the records selected by
those pointers. It never walks retained historical record versions to discover
which entries are current. The explicit independent audit may reconcile against
history; normal operations and maintenance steps do not invoke that audit.

| Boundary | Work bound |
| --- | --- |
| Start, get progress, cancel | Indexed selected job/source/authority lookups and bounded signature checks |
| Each build transaction | At most 32 current pointers and selected record lookups |
| Activate | One generation pointer change plus fixed-size job/event/source updates |
| Each cleanup transaction | At most 32 entries in the retired or abandoned generation |
| Idle scheduler | First unfinished entry in a partial index; no write transaction when idle |

Total rebuilding necessarily depends on the selected current entries to
materialize. It is independent of the number of retained historical versions.
No activation copies an entire table, and no ordinary request triggers a rebuild.

## Availability and failure

The old generation keeps serving throughout construction. Build and cursor
updates commit atomically. After completing the selected source, activation
rechecks source revisions, current Owner authority and deadline, then swaps the
generation pointer in one transaction. It emits a signed-source-linked
`structure.projection.activated` event so observers can refresh their view.
Old-generation cleanup is paged and occurs after activation.

A source write causes `SOURCE_CHANGED` and discards the candidate without
freezing business writes or replacing the prior view. Expiry, revocation and
pre-activation cancellation also prevent activation. Cancellation after
activation does not roll back the applied result. Continuous-write catch-up is
not implemented; this candidate deliberately aborts rather than activating a
stale view or silently blocking writers.

Missing or corrupt verification inputs produce `VERIFICATION_BLOCKED`, not
`REJECTED_NO_EFFECT`. The candidate leaves the ready queue so other jobs can
proceed. An explicit fresh Owner cancellation can discard its isolated scratch
generation without changing or relabelling the invalid historical input.

Job checkpoint/error capacity is reserved on admission, allowing cleanup and
diagnostics without growing that job's logical quota. Capacity failure during
activation rolls back the pointer and refresh event, reports a definite
`REJECTED_NO_EFFECT`, and cleans the candidate. SQL/storage failures retain their
transactional recovery path and are not misclassified as verified business
rejections.

Progress reads are ephemeral by default and do not accumulate snapshots in the
SDK mutation outbox. The driver obtains one nonce-bound service-time window for
its bounded wait, uses selected signed reads and verifies source/actor/protocol
bindings on every observation. It never enumerates all local operations.

## Compatibility limits

The unreleased backend extension v16 creates these stores empty when upgrading
released v15. It does not disclose or reinterpret existing encrypted workspace
history. Incompatible earlier v16 source candidates fail schema validation.

Body-key convenience, default browser routing, actual conversion jobs, explicit
legacy activation, broader installed-platform qualification and production
rehearsal remain separate unfinished deliverables. This derived-index job is
one implemented part of the backend maintenance framework.
