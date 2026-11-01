# Native SDK0.3.2 experimental candidate

Status: unreleased. Exact three-platform assets, checksums and final availability
will be announced only after qualification. Published0.3.1 remains available.
This is a native client update; no service restart, schema change, identity or
workspace migration is required by this release.

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
