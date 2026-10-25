# Backend operation discovery (unreleased candidate)

These APIs describe modified source, not published SDK 0.1.11 packages or a
production service capability. They apply to explicit backend-execution v2
Contexts. Legacy encrypted-history contexts retain their existing contract.

## Find admitted work without scanning client history

```javascript
const page = await context.operations(workspaceId, {limit: 16});
for (const operation of page.result.operations) {
  if (operation.source_verification === 'BLOCKED') {
    // Inspect the selected operation; no successful effects are asserted.
    continue;
  }
  const result = await context.followOperation(workspaceId, operation);
}
```

```python
page = context.operations(workspace_id, limit=16)
operation = page['result']['operations'][0]
result = context.follow_operation(workspace_id, operation)
# Async equivalents: operations_async and follow_operation_async.
```

The default is `scope: 'MINE'`, `view: 'OPEN'`. It uses the selected Context
identity and an indexed backend registry of unsettled operations. Work already
admitted by the backend can be found after switching devices or losing the old
local operation store. Finding that work does not require importing historical
receipts, keys or pending packets.

This is discovery of admitted backend jobs. It does not claim to find a local
mutation that has never reached the service. Preserve the original idempotency
key or saved-command handle for uncertain submission; never mint a replacement
business intent solely because the backend list is empty.

`scope: 'WORKSPACE'` explicitly selects visible workspace operations, including
other authors' work. `view: 'HISTORY'` explicitly pages retained completed jobs.
Membership is checked on every request. The default never enumerates completed
history or filters other actors after collecting their rows.

## Page and source semantics

The backend uses dedicated actor/workspace indexes, including partial indexes
for open work. Each page returns at most 32 entries and has an independent
response budget. `next_cursor` is a service-signed keyset cursor bound to actor,
membership generation, workspace and query filters. Pass it as `after` in the
next `operations` call. No offset or whole-result count is used.

Pages are `LIVE_KEYSET` current views, not a frozen historical snapshot. A job
can finish between pages. A newly inserted ID can precede a traversed key; use
the first page's `observer_checkpoint` and structural events to observe new
admissions. Admission emits `structure.maintenance.ordered`, whose summary
identifies the job. The existing activation event signals a current-view refresh.

Open work includes building, backend cleanup and quarantined work that still
needs attention. Finishing semantic execution does not hide cleanup failures.
The backend clears the indexed unsettled marker atomically when cleanup finishes.

The response includes original author proofs in a source dictionary. Native
verification binds every verified entry to its author, command, workspace,
instance, protocol and source revisions. The signed current progress remains
`BACKEND_CURRENT_STATE`; it is not independent business-history replay.

A damaged source is returned as an explicit per-entry
`source_verification: 'BLOCKED'` diagnostic with a null source. Its observed
stored status is not promoted to an authenticated successful result. Other
entries can still be verified. Selected single-operation reads remain strict;
the diagnostic does not repair or reinterpret historical input.

## Follow from a fresh local store

`followOperation` / `follow_operation` selects the job's workspace, instance,
protocol and ID, signs read-only progress requests and waits within a bounded
30-second driver window. It never imports or resubmits the original mutation,
and following another visible author grants no write authority.

The method preserves the original operation's `command_id` separately from its
`observation_command_id`. A terminal observation returns verified, rejected or
blocked status. If more waiting is needed, the continuation uses
`OBSERVE_SAME_OPERATION` and retains only the selected job identifiers. Call
`followOperation` again with the same descriptor; do not call mutation resume
for a job absent from the local outbox.

Progress reads do not accumulate mutation records or response snapshots in the
new local store. Cancellation stops the wait, not the backend operation. Explicit
Owner cancellation remains a separate signed control action.

CLI equivalents are `context operations` and `context follow-operation` using
the same v2 Context, selected workspace and request JSON. The follow request is
`{workspace_id, intent: {action: 'structure.maintenance.get', instance_id,
protocol_digest, body: {job_id}}}`. Retain the Context fingerprint between CLI
processes.

The currently implemented backend job kind is `CURRENT_RECORDS`. Local legacy
all-pending enumeration, body-key convenience, browser routing and actual
conversion/legacy activation remain separate unfinished work.
