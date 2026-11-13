# Native notification state retention

Native SDK 0.3.30 repairs local notification ledger exhaustion in the resident
Runtime and host-user bridge. Upgrade both original components, preserving their
state directories, identity, journal, pending command IDs and destination. A
frontend update alone does not replace either running process. The service's
existing host-report schema is unchanged; this repair needs no service upgrade.

## Retain live work, not an accumulating copy of every attempt

The Runtime keeps one authenticated, encrypted frozen frame per notification and
binding. Retries share that frame. The bridge stores the exact authenticated
binding, digest and host outcome; it does not keep another rendered body. The
original verified inbox frame remains separate evidence, not another retry copy.

Open calls reserve enough space to persist bounded future outcomes even when
admission fills. Terminal evidence releases unused reservations. Service-confirmed
application consumption releases the frozen payload immediately; pending reports
keep only their scope, digest and original facts. Local consumption requests alone
do not authorize evidence deletion.

Each notification has a monotonic attempt counter. Reported superseded calls can
be retired once the bridge has durably fenced their generation. A lost retirement
acknowledgment resumes the same plan; the bridge commits first, the Runtime
second. Old callbacks cannot overwrite the current attempt. A compacted call is
`HOST_EVIDENCE_RETIRED`, never a newly invented `NOT_SENT` or `HOST_ACCEPTED`.
Existing service-recorded facts and pending business operations are unchanged.

A missing callback is not application consumption. Accepted-but-unconsumed
notifications retain controlled reminders with their existing frozen message ID;
notification delivery remains at least once. Reminders do not resubmit a business
operation. Report upload pressure prevents unlimited successor creation. Consume
a handled notification explicitly, then continue any longer business work under
its own operation ID.

## An old pending item does not pin completed later items

Exact service-confirmed consumption is preserved independently of the finite
1,024-entry local receipt retry cache. Later completed notifications can retire
even if the earliest notification remains pending. Adjacent closed sequence ranges
merge; the confirmed prefix replaces old ranges in bounded maintenance pages.
These guards suppress reinjection without keeping a random tombstone forever for
every old call.

An old unknown or queued host result may retire after exact application consumption
and report confirmation. This ends the notification obligation without claiming
that the old host accepted it. A physically open input retains its writer fence;
retirement does not launch a second writer or cancel a model turn.

## Upgrade an already full ledger

Legacy conversion authenticates and compacts at most 32 old records per pass,
without needing a fresh normal-call reservation. Maintenance and receipts remain
available while new-input admission is full. Subsequent passes continue from
stored conversion state; no full history replay, VACUUM, journal deletion or
receiver reset is needed.

Legacy records whose completion cannot be proven remain retained. In particular,
an absent cache entry is not a consumption receipt. Invalid ciphertext is retained
and reported rather than silently discarded. A real backlog of live work or
unreported facts still has a finite storage budget and applies explicit
backpressure. Logical free space and the reusable SQLite file size are different.

`HOST_STATE_CAPACITY` diagnostics identify local notification storage, its used and
required bytes, limit and retained call count. It is distinct from a Workspace
byte/object quota, a full inbox, service rate limiting or an offline host. Increasing
a server quota does not repair an old local notification ledger implementation.

## Adjacent storage review

The verified inbox already retires exact consumed items and unused frames; its
key prerequisite queue removes references when those items end. These are live
work queues, not one persistent copy per host attempt. The Claude Channel reads
the original inbox and keeps a bounded notification window rather than a second
on-disk message history.

Business-operation receipts have a different purpose: they preserve operation-ID
idempotency, frozen inputs and uncertain mutations. They are not deleted by this
notification repair. Native 0.3.30 also corrects their retained resolved-input byte
accounting, including bounded legacy accounting recovery. An operation or inbox
budget filled by real retained work remains a distinct, explicit capacity limit.

## Verification scope

Regression tests use temporary synthetic identities and SQLite state. They cover
an early unconsumed hole, receipt-cache rollover, repeated unknown retries,
monotonic generations, delayed callbacks, same-state restarts, invalid encryption,
full legacy ledgers and authenticated bridge retirement. Existing host-offline and
write-contention tests exercise transport separation. These tests do not attest
that an installed real Agent session has received or answered a message; verify
that separately after upgrading the original receiving stack.
