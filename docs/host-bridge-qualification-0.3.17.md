# Native0.3.17 bridge qualification

Runtime/archive source: `f8b65d6ba918694d8b5b2c1650e023e48a839ddf`.
Linux CI run: [42180512835](https://github.com/peerwork-dev/peerwork-sdk/actions/runs/42180512835).
The installed archive was downloaded unchanged, with binary SHA256
`b4b4993760f27a9b4baa11cc760c3180f9ef32d89fdb29a3a5ac45b972c1792e`.
All execution used designated local TEST resources and synthetic identities/data.

| Check | Passed |
| --- | ---: |
| Codex and supported AGY adapter/process contracts | 20 |
| Durable bridge, deadlines, offline receipts and stalled-provider faults | 16 |
| Runtime IPC, selected client/generation diagnostics and automatic recovery | 18 |
| Original-call ledger and scope isolation | 12 |
| Dispatcher shutdown/ownership | 2 |
| First-host and resident rebind/recovery | 20 |
| Physical host ownership | 3 |
| Controlled official Codex full receive after unload | 1 |

The exact CI executable additionally passed its real native bridge serving and
shutdown case, and a separate signed HTTP/MCP flow using a synthetic service and
resident event worker. That flow retains original-operation recovery, observes
membership/event tools and finishes its synthetic deletion and runtime shutdown.
Two focused real HTTP/browser cases qualify the updated website links on desktop
and mobile. The frozen PUBLIC image also starts under its configured UID1000 and
normal entrypoint without any database operation.

## What the official-host case establishes

An isolated official Codex App Server0.166.0 starts one selected conversation with
a deterministic loopback Responses provider. After its initial turn completes,
the driver unsubscribes and waits for actual `notLoaded`; repeated `thread/read`
does not load/subscribe to it. The SDK restores that exact thread/session, retains
the original receiver and delivers only the pending message. The already-consumed
message does not become another host input. The final host has exactly two model
requests/turns: initial setup plus one pending delivery. Both host and driver are
terminated and reaped afterward. No user conversations, credentials or paid model
service are used.

The single observation from rebind through local HOST_ACCEPTED was1814ms. This
is a controlled functional sample, not a percentile benchmark, production capacity
claim or inference-response guarantee. Host receipt upload was still pending when
the observation was captured; HOST_ACCEPTED is the recipient runtime's durable
fact, distinct from service upload and model completion.

Maintainers can use `tools/test/isolated-codex-host.mjs` with an explicit official
0.166.0 executable in `PEERWORK_TEST_CODEX_EXECUTABLE` and a fresh output directory.
Compile the Rust test binary **before** starting this bounded-lifetime driver.
Wait for its `ready.json`, then set `PEERWORK_CODEX_CONTROL_CONFIG` to the emitted
protected `adapter.json` and `PEERWORK_OFFICIAL_HOST_REPORT` to a fresh report path.
Run the explicitly ignored test
`official_unloaded_codex_receives_original_pending_mail_once` with the synthetic
PostgreSQL/HTTP fixture environment described in the reliability guide. Stop the
owned driver with SIGTERM after checking host state and its terminal report.
Node is a test dependency here; it is not a native client installation dependency.

## Corrections retained in evidence

Earlier attempts retained missing fixture configuration and assertions that still
expected synchronous health/manual recovery. One concurrent compilation was
SIGKILLed under TEST memory pressure; later builds were serialized. An empty test
selector was rejected as evidence and rerun with the exact module and ignored
loopback tests enabled. The first official full-chain test queried before its
watch registered, producing WATCH_NOT_FOUND; test-only successor `397578a` adds a
bounded startup wait. The released runtime is unchanged:260 native semantic files
were independently hash-matched. This test correction does not change the frozen
archive/tag. The helper and this report are follow-up source documentation.

Fault fixtures exercise partial handshakes, stalled host/ledger operations,
reservation after budget expiry, panic after possible input, persisted unknown
calls and original-scope isolation. They do not prove recovery through arbitrary
kernel/storage failures. A possibly accepted call without authoritative host
readback intentionally remains unresolved; no test claims exactly-once model
execution or repairs every host-reported system error.
