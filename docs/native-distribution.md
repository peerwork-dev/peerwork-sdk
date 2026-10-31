# Native participant distribution

The native 0.3.0 interface is an **unreleased experimental candidate**. The
production service advertises `native-mailbox-v1` and `native-mailbox-rebind-v1`;
that does not announce a client release. Published SDK0.2.16 and Agent tools0.1.0
remain separate older interfaces. Do not install an old wheel and expect native
0.3 operations, or replace an existing listener without explicit state takeover.

## Supported distribution targets

| Target | System requirements | Additional client language runtime |
| --- | --- | --- |
| Linux x86_64 GNU | glibc2.28+, system libstdc++ and libgcc; exact imported ABI requirements are recorded per artifact | None |
| macOS ARM64 | macOS11+, system frameworks and C++ runtime | None |
| Windows x86_64 | Windows10+, native system APIs; selected build statically links the VC runtime | None |

Archives contain the `peerwork` executable (`peerwork.exe` on Windows), the
portable `skills/peerwork/SKILL.md`, project license, dependency SBOM and complete
third-party license notices. They contain no identity, host access credential,
runtime configuration or model. Apple signing/notarization and Windows publisher
signing are not claimed for these candidate archives.

Rust programs embed `peerwork-runtime` from a pinned source commit. Programs in
other languages can speak bounded local JSONL to the same resident runtime;
there is no separate handwritten SDK mirror to keep in sync. CLI and MCP tools
use the protected scoped endpoint and the shared signing/E2EE/recovery engine.
The service and maintainer fixtures may use Node or Python; those are not client
installation dependencies. A selected Codex/AGY host and its own supported
runtime are prerequisites only when requesting delivery into that host.

## Build once, qualify, promote the same bytes

The active workflows are source/native checks and deliberate three-target native
qualification. The old language-binding distribution, eight-artifact publisher,
tag-triggered Linux binding builder and full duplicated release matrix have
been retired. Existing public releases remain available; no workflow silently
publishes a new package on source backup or a qualification push.

`python tools/release/version.py check --native` validates the shared Cargo
version, locked CLI/core/runtime versions and exact native target set. Frozen
Node/Python package versions are outside that cohort. The native qualifier checks
the complete selected dependency/license graph before compilation, uses cached
builds, exercises protected installed-process recovery and audits actual loader
imports. Node is used on eligible CI hosts solely to produce a historical
receiver-store fixture. It is not packaged or installed for users.

All three archives must come from one successful qualification source/run.
Promotion must retain those exact archive bytes and record source commit,
source tree, run/artifact IDs, archive/binary hashes, target requirements,
notices and explicit qualification limits. It must not reconstruct binaries,
mix runs, erase a failed case or imply code signing. Verify anonymous download
bytes after publication. A successful source checkpoint or CI artifact is not
itself a public release.

Experimental maturity describes the interface in a binary. Publication is an
external fact established by the release and its source/asset manifest, not a
hardcoded `UNRELEASED`/`RELEASED` response. Likewise, `LOCAL_READY`, service
acceptance, receiver storage, host acceptance, model reply and business completion
are different observations. Packaging checks do not establish real-host IM
latency percentiles or automatically authorize an existing consumer takeover.

Start with the [Agent and program quickstart](native-participant-quickstart.md).
See the [participant contract](participant-runtime-candidate.md) for program,
Agent, authority, maintenance and recovery interfaces. Use a matching public
release only after its availability is explicitly announced.
