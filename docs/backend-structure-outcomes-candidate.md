# Terminal outcomes and recovery

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

A submission has one of three distinct facts: a confirmed business outcome,
a confirmed refusal with no business effects, or an uncertain delivery. The
SDK does not infer any of these from HTTP status alone.

## Confirmed refusal

For a known signing actor or an admitted member, authorization failure is
recorded under the original actor/workspace/command key only after the failed
transaction has rolled back. The service serializes the decision with concurrent
submissions of that command. A signed `REJECTED_NO_EFFECT` receipt confirms
`NOT_APPLIED` and includes phase, code, retryability and recovery instructions.
The public SDK outcome is `REJECTED`; Contexts return `status: 'rejected'`.

The SDK retains the proof and removes the operation from its pending index.
Changing permissions later does not make that command eligible to execute.
A new business request requires a new operation. Reopening with a fresh local
journal also recovers the original refusal, rather than applying it again.
Rejected commands consume their actor's accounting scope rather than the target
workspace's write budget.

Never-admitted anonymous keys cannot allocate permanent refusal records. Read
refusals are signed without recording every page/read as durable server state.
Unsigned failures before admission remain unconfirmed; they cannot be used to
retire a potentially submitted operation.

## Confirmed commit with temporarily unavailable data

A reply can be lost after commit, followed by membership revocation. In that
case, the service must not report that the original command had no effects.
It returns a signed `COMMITTED_RESULT_UNAVAILABLE` acknowledgment instead. The
public SDK outcome is `COMMITTED`; Contexts return `status: 'committed'`.

This acknowledgment contains only the caller's original intent identifiers and
commit fact. It excludes workspace state, produced records and other actors'
data. The full committed receipt remains unchanged on the service.

The SDK closes submission uncertainty and never posts the original mutation
again. After access is restored, repeating recovery fetches the original
signed result with an indexed read and upgrades the local acknowledgment to
that full receipt. It does not recreate the operation. A full committed result
and a signed refusal are never treated as equivalent facts.

## Uncertain delivery

A timeout, lost reply, unsigned proxy failure or invalid signature leaves the
operation pending. Recovery retains the original signed intent and operation
ID. Retries are bounded and cannot silently replace business fields or CAS
expectations. An unsigned 401/403 is not proof of a final refusal.

A later service-signed observation can resolve uncertainty. Only receipts
verified against the selected origin's pinned key, the original author and the
same business intent may finalize or upgrade the local outcome.

## Diagnostics

Confirmed refusals expose the signed `error` object on the verified structure
result. Higher-level preflight/selected-key failures retain structured details,
including the server code, phase, HTTP status and recovery. Kernel errors expose
these in `details`; Context error envelopes preserve the corresponding fields.
Proxy-only HTTP failures retain their status while reporting uncertain effect.
No raw SQL, connection string, private body or key is included in diagnostics.

A refused observation of a background job does not mark the job itself failed.
It remains a request to observe the same operation after authority is restored.
