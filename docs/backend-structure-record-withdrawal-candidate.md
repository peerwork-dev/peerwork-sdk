# Selected record withdrawal — source candidate

This capability is implemented and being qualified locally. It is not a statement
of production availability or a released SDK version. Discover
`selected-record-withdrawal-v1` before submitting `structure.record.withdraw`.
Use `backend-structure-v1`; legacy execution modes remain retired.

## One signed operation

```js
const outcome = await kernel.executeStructureIntent({
  action: 'structure.record.withdraw',
  workspace_id: workspaceId,
  instance_id: instanceId,
  protocol_digest: protocolDigest,
  expected_instance_revision: currentRevision,
  idempotency_key: 'withdraw-selected-record-once',
  body: {record_id: recordId, revision: recordRevision}
});
```

Python uses `KernelClient.execute_structure_intent` (or its async variant) with
the same selection. The CLI accepts that JSON through `peerwork kernel intent`.
A selected Context accepts the same operation with its workspace selected
separately. All facades use the native durable operation implementation.

Only the original record author or an active workspace Owner may withdraw the
selected immutable record version. Workspace membership and access expiry still
apply. Withdrawal is independent of an expired business grant or a disabled
publication policy. The expected instance revision is mandatory. A successful
transaction advances both instance control and event revisions; stale revisions
fail without an implicit rebase.

## Observable result

The same transaction stores a withdrawal marker, removes the selected record
from current indexes and any PUBLIC projection, and seals the original signed
outcome. It does not scan or rewrite retained versions. At most the active and
candidate/cleanup current-index generation is touched. A live rebuild cannot
reintroduce the withdrawn row.

Subsequent selected reads, publication preparation, republishing, exact-input
consumption, revisions using that parent, relations and head selection reject
`RECORD_WITHDRAWN`. The selected-read refusal is service signed, has
`effect_certainty: NOT_APPLIED`, `retryable: false`, and
`recovery: SELECT_ANOTHER_RECORD`. Reads allocate no durable mutation slot.

Other immutable versions preserve their own visibility. Withdrawing the current
head leaves no current record for that entity; it does not select an older
version automatically. Existing downstream records and business state are not
rewritten or cascaded. A protocol that needs a business-level cancellation must
express that transition separately. This platform action does not change the
semantics or support status of the manifest `withdraw` effect.

## Recovery and retained evidence

An uncertain submission returns its durable original operation ID. Resume that
ID with `resumeStructureIntent`, `resume_structure_intent`, or the CLI rather
than inventing another withdrawal or repeatedly rebuilding state. An accepted
original operation remains accepted on exact replay even after withdrawal has
removed the selected current row. A newly identified withdrawal of the same
record returns `RECORD_WITHDRAWN`.

The service retains immutable records, author commands, receipts and withdrawal
evidence for verification. Withdrawal prevents normal business use; it is not
cryptographic erasure of retained evidence or revocation of previously delivered
plaintext, ciphertext, keys or public replicas. Existing historical command
proofs remain subject to their workspace access rules. Whole-workspace physical
deletion is a separate operation and release requirement.

Cross-instance consumers take a shared lock on the exact selected record;
withdrawal takes its exclusive record lock. The visibility check occurs after
the fence is acquired. A consumer admitted first may commit before withdrawal;
a consumer acquiring the fence after withdrawal must reject the reference.
No lock or replay of the consumer's full workspace is needed.

## Schema

The explicit PostgreSQL9-to10 migration adds an indexed withdrawal table. It does
not rewrite records, author packets, receipts, identities, grants or body keys.
An SDK without the discovered capability refuses locally before preparation or
submission. Source candidates built with the local development0.1.11 package
metadata must not replace the already published0.1.11 release.
