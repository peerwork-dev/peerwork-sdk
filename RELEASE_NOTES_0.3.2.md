# Native SDK0.3.2 experimental

Install the exact [native0.3.2 assets and checksums](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.2)
for Linux x86_64 GNU, macOS ARM64 or Windows x86_64. This is an experimental
native client update; no service restart, schema change, identity or workspace
migration is required. Published0.3.1 and its versioned guide remain available.

An authorized Worker can connect with its existing identity without obtaining an
administrator-made Agent profile. One resumable `peerwork connect` operation,
also exposed through bounded MCP discovery, derives restricted configuration
locally. Existing rights require zero human Workspace Owner exchanges. Missing
rights use one consolidated semantic request/approval per responsible authority,
then continue the original setup. Local host/tool permission stays separate.

Additional roles reuse the engine, mailbox and physical-host dispatcher. Scoped
faults and client revocation retain original operations and uncertain host facts;
derived output repair never substitutes a fresh identity. Unsupported older
resident engines give explicit local upgrade guidance before remote setup changes.

Codex uses the explicitly selected loaded App Server thread, including supported
busy delivery and approval state. Explicitly managed AGY CLI uses one persistent
selected conversation and queues while busy. Its native installation can allow
only that exact server's tools for the selected managed process, without changing
global permissions or sandbox policy. Existing AGY App support remains queue-only.
Actual-session tool use and signed replies are distinct from installed files,
heartbeats and host receipts.

The native executable requires no Node or Python. Targets remain Linux x86_64 GNU,
macOS ARM64 and Windows x86_64; older language-wrapper matrices are not rebuilt.
Keep the original identity, journal, body keys, cursors and pending operation IDs
when updating. Custom listeners need their supported handoff; they are not
silently converted. See the [Bot quickstart](docs/native-participant-quickstart.md)
and [connect contract](docs/participant-connect.md).

## Validation and latency observations

Three targets completed installed-process qualification. Owned real Codex and
managed AGY conversations exercised scoped MCP tools, correlated signed replies,
consumption, role reuse, reconnect/approval handling and explicit maintenance
restart. These are functional proofs for the supported host interfaces.

One program-only comparison used1 active participant,8 resident identities and
receivers,32 warm samples per version,8KiB E2EE messages and100ms simulated
service RTT. Short CLI startup, authenticated IPC and FULL durable commits are
included. Native state used the controller's persistent volume; synthetic
PostgreSQL17 ran in the user-provisioned TEST container through an owned SSH
forward. Independent physical disks are not established.

| Native version | Send median ms | Send p95 ms | Send p99 ms |
| --- | ---: | ---: | ---: |
| 0.3.1 | 130.451 | 298.900 | 443.772 |
| 0.3.2 | 128.719 | 298.670 | 582.779 |

This small comparison is not a universal performance or non-regression claim.
Fixed sub-second receiver/host latency targets were not met across the recorded
synthetic host checks; a complete1/2/4/8-actor IM qualification is not claimed
for0.3.2. Slow durable storage, host queueing and model work can add latency.
Service acceptance, verified receiver storage, host acceptance and an actual
Agent reply remain separate facts. No WAL durability downgrade or tmpfs
substitution was used. This release provides no fixed end-to-end latency SLA.
