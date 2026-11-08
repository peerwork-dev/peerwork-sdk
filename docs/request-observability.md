# Request volume and admission diagnostics

Service capability: `admission-retry-hints-v1`, execution profile
`backend-structure-v1`. SDK 0.2.3 remains compatible; no SDK binary upgrade is
required for server-side request accounting. Check discovery for availability.

## What is counted

Control records completed HTTP requests by UTC minute, status code, bounded
route category, verified structural action and admission refusal scope. Reads, writes and recovery queries
are included, along with health checks and discovery. These are HTTP request
counts, not business-operation counts: one SDK operation may make several HTTP
requests. A request completing across a minute boundary belongs to its completion
minute. Latency sums and maxima are also recorded.

Actor series use hashes of signature-verified actor IDs. Source addresses are
pseudonymized per process. Each series retains at most 64 distinct principals
plus an OTHER aggregate, preserving total counts when cardinality is higher.
Raw paths, query strings, bodies, signed packets, keys and raw IP addresses are
excluded. No public endpoint exposes private request diagnostics.
At most 32 refusal samples per minute retain correlation IDs, scope, retry hints
and verified command IDs when available. Further refusals remain in aggregate
counts and an explicit sample-overflow counter. Requests rejected before signature
verification have no attributed actor or command ID.
Sanitized service error codes distinguish frequency admission from resource or
quota refusals that also use HTTP 429. These appear as `non_admission`; a 429
without a known service code remains `unclassified`. An HTTP 429 alone is not
evidence of excessive request frequency.

Control persists cumulative snapshots about every ten seconds and on graceful
shutdown, independently of disposable application containers. Records include
a process ID, minute, monotonic snapshot sequence and completeness marker.
Queries select the latest snapshot for each process/minute, then sum across
process restarts; repeated snapshots must not be added together. Persistence
runs outside business transactions and the request's I/O path. A health status
reports persistence failure or discarded windows instead of silently claiming
complete coverage.

Retention is up to seven days, bounded to eight files of eight MiB each.
Abrupt termination can lose requests since the last flush. Missing minutes mean
missing evidence, not proof of zero traffic. Requests blocked by Cloudflare or
another upstream before reaching Control are outside these counts. This change
cannot reconstruct requests made before collection was enabled.

## HTTP 429

Admission refusals return `Retry-After` in whole seconds, an
`X-Peerwork-Request-Id` correlation ID when collection is enabled, and a bounded
error object:

```json
{
  "error": {
    "phase": "ADMISSION",
    "code": "ADMISSION_RATE_LIMITED",
    "http_status": 429,
    "retryable": true,
    "recovery": "RESUME_SAME_INTENT",
    "request_id": "SERVER_GENERATED_ID",
    "rate_limit": {
      "scope": "actor",
      "limit": 1200,
      "remaining": 0,
      "window_ms": 60000,
      "reset_at_ms": 1793077860000,
      "retry_after_ms": 15000
    }
  }
}
```

Scopes are `actor`, `source`, `global`, or `capacity` for exhausted admission
counter capacity. Configured limits are discoverable and are not observed
request rates. The underlying process-local abuse counters still reset on
process restart; diagnostic history is separate from authorization or quotas.

These unsigned HTTP hints do not prove that an earlier attempt of the same
operation failed to commit. Preserve the original operation ID and resume it
with the original identity and journal. Do not create another operation to
resolve uncertainty. SDK 0.2.3 reports `PENDING / RATE_LIMITED` but does not yet
expose these response headers or error details; operators can use the persisted
server aggregates independently. Automatic SDK backoff and separate recovery
admission budgets are not introduced by this monitoring update.
