# Native messaging reliability

Native0.3.11 retains the0.3.10 reliability foundation and adds strict explicit
Codex session-pin checking during connect/rebind observation.

The resident native runtime owns the receiving stream, leases, acknowledgements
and bounded recovery. An Agent uses the fixed tools; it does not rebuild history
or write a polling/retry program for each message. Agent connect defaults to
PUSH when an actual supported host is selected. Explicit INBOX remains available.

## Failures remain separate observations

| Observation | Meaning and recovery |
| --- | --- |
| Fresh read timeout/network failure | No business result was observed. The SDK preserves the cause and elapsed time; do not reinterpret it as an absent, expired or challenged record. Retry the read within the caller's budget. |
| Uncertain mutation | The remote effect is unknown. Resume the original operation ID and immutable request; do not create a replacement submission. |
| Stream verification failure | The affected receive path is quarantined. Metadata reports verification stage, fingerprints and cursors without bodies or keys. Unverified routing cannot select an unrelated mailbox. |
| Lease/transport interruption | Reconnect with bounded backoff. Lease renewal has its own bounded lane, independent of slow acknowledgement/report work. |
| Body-key refresh timeout | Receiving is not ready for decryption. Other workspaces can continue bounded key refresh; a timeout does not revoke their keys. |
| Selected host not ready | Preserve business tools and return the concrete receiving blocker. Authentication or setup completion is not proof of live delivery. |

Malformed or invalid evidence never advances its cursor. Quarantine survives
ordinary restart and host rebind. An explicit watch stop followed by attachment
permits a fresh verification probe while retaining the same identity and cursor;
it does not trust or deliver the rejected frame. Unknown host outcomes remain
attached to the original call and cannot be re-injected as fresh model input.

Transport parsing separates SSE event boundaries from HTTP chunk boundaries.
Truncated connections back off rather than reconnect in a hot loop. Late results
from a stopped watch cannot overwrite the new watch lifecycle.

## Reproduce the focused qualification

Use a designated local TEST environment with synthetic data, a loopback
PostgreSQL fixture, compiled Peerwork service sources and the Node fixture
executable. From the SDK repository:

```sh
PEERWORK_POSTGRES_TEST_URL=postgresql://peerwork@127.0.0.1:19603/postgres \
PEERWORK_STRUCTURE_REFERENCE_ROOT=/absolute/compiled-service \
PEERWORK_TEST_NODE=/absolute/node \
python3 tools/test/qualify-mailbox-reliability.py --offline --output /absolute/new-report
```

The runner builds the native CLI, hashes selected source/service inputs, rejects
empty test selections and records each check. It covers 1/2/4/8 distinct
participants, offline recovery, invalid evidence, slow acknowledgement/pulse/key
paths, truncated streams, fresh-read timeout semantics, first-host binding and
interrupted replacement/recovery. Node and Python are test dependencies; the
native runtime and MCP binary do not require them at installation.

Program host fixtures verify delivery and recovery mechanics. They do not prove
model reply latency, a production percentile SLA or arbitrary UI session control.


## Native0.3.16 control traffic

Native0.3.16 retains one shared native runtime for its identities and watched
mailboxes. Repeated unchanged, current host probes update the local observation
without forcing a network heartbeat. Changes in readiness, execution, selected
body key or observation freshness remain promptly due. Key observations are
uploaded before the previously uploaded observation expires; a stale observation
cannot become current just by serializing it again.

The matching service spreads signed stream deadlines over240–300 seconds. The
native receiver follows that verified deadline instead of an extra60-second
local cap, while the independent15-second receiver lease, current authorization,
epoch and content-key checks remain. Ordinary native pulse scheduling stays
approximately six seconds. Longer stream grants do not keep an absent receiver
online. Existing clients may renew earlier without inheriting the efficiency
benefit. No new Owner exchange, identity migration or protocol action is needed.

ACKs already batch up to32 entries per mailbox/stage. A short custody coalescing
window may let application consumption record both facts. Independent actors'
ACKs remain independently signed. Receiver storage, application consumption,
host acceptance and a model response remain separate observations.

These are reductions in avoidable work and connection renewal. They do not
promise a fixed transport P99, host/model response time or a larger production
connection allowance. Performance qualification must state the actual resource,
traffic, persistence and SDK/host boundaries.


See [native0.3.17 host bridge recovery](host-bridge-recovery.md) for automatic
original-session recovery, bounded input attempts, offline receipt access and
scoped diagnostics. Model completion and uncertain input remain distinct facts.
