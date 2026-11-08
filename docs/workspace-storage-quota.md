# Workspace storage capacity and advance warnings

Service capability: `workspace-storage-warnings-v1`. SDK **0.2.4** adds resource
error classification and automatic warnings in Node, Python and CLI. Older
clients remain compatible, but SDK 0.2.3 labels unreceipted HTTP 429 responses as
`RATE_LIMITED`, including storage quota failures.

Each workspace has an independently configured total byte limit and object
limit. Administrators can increase the selected workspace without changing
other spaces, identities, encryption keys or protocol permissions. Capacity
updates preserve existing usage and global reservation bounds. They do not
reserve the workspace's entire limit globally; credit grows in bounded blocks
as storage is used. The current global bounds still apply.

Ordinary writes retain a safety reserve of one MiB and 1,000 objects for security
operations. For example, a 100 MiB total limit permits up to 99 MiB of ordinary
writes. One MiB is 1,048,576 bytes. Capacity measures retained logical rows,
including encrypted content, historical records, signatures, command evidence
and metadata. It is not disk free space or RAM usage.

A signed `structure.workspace.get` response includes `capacity` with total and
ordinary-write limits, committed usage and remaining capacity. Authorized reads
and successful submissions additionally carry `warnings` when committed usage
has reached **80%** (WARNING) or **95%** (CRITICAL) of the ordinary-write byte or
object limit. The percentages are integer values. Warnings are based on the
committed usage observed inside that request's transaction; a large write may
cross a threshold before the next observation. They do not promise that an
arbitrarily large next write will fit.

The private browser displays an inline warning, available capacity and a request
to contact the workspace administrator. SDK Node/Python warn on entering a new
warning level, suppress repeated same-level console messages per client, and
retain the structured warnings in the verified result. The CLI writes warnings
to stderr while preserving JSON output. No private body, signing seed or body
key is part of the notice.

```js
const outcome = await client.executeStructureIntent({
  action: 'structure.workspace.get', workspace_id: workspaceId, body: {}
});
console.log(outcome.result.structure.capacity);
console.log(outcome.result.warnings ?? []);
```

In SDK 0.2.4, a resource HTTP 429 preserves `RESOURCE_EXHAUSTED`,
`CAPACITY_RESERVATION_EXHAUSTED` or the corresponding bounded resource code.
Automatic retry is disabled for these hints; increasing capacity or reducing
retained usage requires administrator action. A true admission-rate 429 remains
`RATE_LIMITED`.

HTTP resource diagnostics are **unverified hints**, not proof that an earlier
attempt of the operation failed to commit. Without an accepted verified result,
the SDK keeps `PENDING`, `effect_certainty: UNKNOWN` and the original command ID.
After capacity becomes available, resume that original operation with its
original identity and journal. Do not create another ID to resolve uncertainty.
Neither capacity warnings nor a quota increase change business approval states.
