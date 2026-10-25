# Durable structure operations (unreleased source candidate)

This describes a locally qualified source candidate, not an available production
service or published SDK version. It shares the native operation implementation
across Node, Python and CLI.

## One operation across preparation and submission

A durable structure intent is saved before its first remote prerequisite. The
selected service, audience, signing identity, authority, workspace and command ID
bind its encrypted local plan. AES-256-GCM uses a fresh nonce and a domain-separated
key derived from the selected identity seed. Private staged text is absent from
SQLite rows, WAL and public pending diagnostics in plaintext. The service does
not receive the plan or its local encryption key.

Business inputs remain immutable for an idempotency key. Changing them returns
an intent conflict before another prerequisite or business submission. Concurrent
producers elect one plan and one exact signed packet. Recovery does not replace
business CAS constraints, invent a new business operation or replay workspace
history.

The native phases are:

| Phase | Durable source | Meaning |
| --- | --- | --- |
| `PREPARATION` | Encrypted selected plan | Parent business command has not been submitted. A separate crypto prerequisite may have its own saved outcome. |
| `SUBMISSION` or existing recovery phase | Original exact signed packet | Submit or reconcile this same operation; a timeout does not establish non-commit. |
| Accepted, rejected or committed | Verified original receipt | Preserve this outcome even when optional local key delivery or richer result retrieval is unavailable. |

An approval plan also saves the normalized original access selection before
nonce-bound time checks, workspace reads or HPKE packaging. Once its signed packet
exists, repeating an approval or resuming its command ID reconciles that packet.
It does not require the original human approval window to be newly valid.
A preparation that never produced a packet must still satisfy the original
request's expiry and authority when it is resumed; recovery does not extend that
permission.

`executeStructureIntent`, `authorizeAccess` and their command-ID resume paths
share a 30-second asynchronous call budget across discovery, preparation,
submission and optional result/key enrichment. The deadline is cooperative;
protected-file and SQLite lock operations have their own finite local limits.
An elapsed preparation budget returns a resumable parent ID with
`phase: PREPARATION`, `effect_certainty: NOT_SUBMITTED` and
`recovery: RESUME_SAME_INTENT`. It never directs recovery to a missing signed
packet. Other standalone maintenance coordinators retain their documented
budgets; this change does not claim that every SDK entry point uses this parent.

A fresh selected read without an explicit command ID/idempotency key remains a
bounded read and does not create a durable parent or a historical query archive.

## Recover after process exit

Use the returned command ID, or repeat the same intent/idempotency key. If a
process exits before returning a generated ID, inspect local preparation pages:

```javascript
const page = await kernel.pendingPage({limit: 32});
for (const preparation of page.preparations.items) {
  const outcome = await kernel.resumeStructureIntent(preparation.command_id);
  // Inspect the verified outcome or keep its original pending continuation.
}
const next = page.preparations.next_after;
if (next) await kernel.pendingPage({preparationsAfter: next, limit: 32});
```

```python
page = await kernel.pending_page_async(limit=32)
for preparation in page['preparations']['items']:
    outcome = await kernel.resume_structure_intent_async(preparation['command_id'])
next_after = page['preparations']['next_after']
if next_after:
    await kernel.pending_page_async(preparations_after=next_after, limit=32)
```

```sh
# page.json: {"limit":32}; both pages have independent command-ID cursors.
peerwork kernel pending-page "$ORIGIN" "$JOURNAL" "$IDENTITY" page.json
peerwork kernel resume-intent "$ORIGIN" "$JOURNAL" "$IDENTITY" "$COMMAND_ID"
```

Existing `items`/`next_after` still describe saved signed submissions.
`preparations.items`/`preparations.next_after` describe saved plans without their
parent packet. Each page selects at most 32 operations using an identity and
command-ID index. Inserting the signed packet atomically removes its preparation
locator. Completed history is never scanned to find pending work. No private
body, approval JWS or encrypted packet is exposed by this locator.

Native journal schema 5 to 6 adds empty tables, an index and an insertion trigger.
It preserves existing packets, receipts, service pins and pending-index
checkpoints. It performs no retained-history backfill. The encrypted immutable
plan remains available for input binding after the preparation locator retires.

## Qualification and remaining boundaries

Actual installed npm, wheel and CLI recovered synthetic Node preparations against
a real isolated PostgreSQL service: Python finished the body submission, CLI
finished the access approval, and all three listed preparations without network
reads. Repeating committed operations while prerequisite requests were blocked
returned the original receipt and produced one business record. Preparation
state did not contain the synthetic plaintext. Selected reads made zero journal
requests. Native tests also cover ciphertext substitution, changed authority or
workspace, concurrent preparation and additive local schema upgrade.

A body write or key-bearing approval by the Owner now repairs an expired or
revoked head automatically before its own submission. It reuses the durable
native crypto producer, preserves the original business CAS and recovers an
uncertain child through the business parent's continuation. Ordinary members
receive no Owner authority. See [canonical key epochs](backend-structure-content-keys-candidate.md).

Head publication and recipient delivery are separate operations. Publishing a
usable head can unblock the Owner business operation while its persistent
backend delivery job is still pending. The native CLI key worker can finish that
job without Agent-written polling or per-recipient orchestration. Approval,
business acceptance and another device's body readiness are distinct.

The default approval still selects only the current key. The separate explicit
[retained-history policy](backend-structure-retained-keys-candidate.md) now authorizes
a bounded historical range and a native delivery job. Historical material does
not reset a newer current selection. The backend never receives body keys.
