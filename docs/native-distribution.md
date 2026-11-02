# Native participant distribution

The native0.3 interface is **experimental**. Install only the matching assets
listed in the [public releases](https://github.com/peerwork-dev/peerwork-sdk/releases)
and verify their source/asset manifest. The target service must advertise
`native-mailbox-v1` and `native-mailbox-rebind-v1`. Older SDK0.2.16 and Agent
tools0.1.0 remain separate interfaces. Do not install an old wheel expecting
native0.3 operations. Existing state and host selections use the
[explicit transition paths](native-state-handoff.md).

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
other languages can invoke the native CLI with bounded JSON requests to the
same resident runtime; authenticated local RPC is not a plaintext socket API.
There is no separate handwritten SDK mirror to keep in sync. CLI and MCP tools
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

Every published archive must have a passed target job and a source-bound
qualification report. All targets of a version use the same frozen client
source; a capacity-only retry may use a separately reviewed workflow that
checks out that exact source. Never infer a passed target from a sibling job.

Targets may become available incrementally. SOURCE.json and SHA256SUMS are
immutable snapshots of the initial publication. Pending targets are explicit;
they are not qualified or downloadable until their actual assets are added.
A later complete source manifest/checksum supplement may be appended without
replacing previously published bytes. The actual release asset list is the
availability authority.
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

## Recorded native0.3.1 communication qualification

The Linux client from source `18f4ea283ac5352b36786a49554c299cb7d4bed6`
completed the recorded1/2/4/8-active-participant qualification with32 warm
samples per case,8KiB encrypted bodies and100ms simulated Agent-to-service RTT.
Sender-acceptance p95 was148–236ms for Codex and136–164ms for AGY CLI1.4.12.
The measured durable-receiver and host-acceptance bounds also passed. The
[release notes](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.1)
record the per-case results and qualification scope.

The AGY run used direct persistent native SQLite state and an independent
PostgreSQL17 persistent volume; the Codex run retained its original local
fixture setup. Storage placement is part of these measurements. FUSE-backed
AGY state remains outside the qualified sender-performance scope. Select a
persistent local state directory for latency-sensitive use and retain FULL
sync. These results do not establish model-response latency, busy/approval
waiting time, arbitrary host configuration or real-host behavior on every OS.
Desktop qualification covers the process/OS checks in the platform reports.

Queued0.3.1 mutations omit one redundant scheduling commit. Original requests,
exact packets and final verified outcomes retain FULL durability. A current
`RUNNING`/`LOCAL_RUNTIME` observation is separate from a verified remote effect;
recover uncertain work by its original operation ID. See the
[state reference](native-state-handoff.md). No identity/workspace migration is
required for this patch.


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

## Native0.3.3 first-use connection

Native0.3.3 keeps the same three native targets and no Node/Python client runtime.
Its platform reports qualify the exact source/run and installed-process behavior.
The release also exercises original0.3.2 registry recovery, bounded project-source
discovery, original namespace/binding checks, tools-only Agent receive, and
permission/key/host continuation through real synthetic-service HTTP.

Older resident runtimes need their local owner's normal update for
`original-engine-binding-v1`, retaining original state, journal and pending IDs.
No automatic binary update or identity/workspace migration is implied. Automatic
attachment to arbitrary existing Codex UI/CLI and external push into arbitrary
interactive AGY CLI remain outside support. A local owning-host callback API does
not supply that integration. Earlier numerical performance observations retain
their original versions and scopes;0.3.3 claims no new full1/2/4/8-agent latency
qualification or fixed end-to-end SLA. See the [current quickstart](native-participant-quickstart.md).

## Change-scoped qualification for native0.3.4

Shared onboarding semantics, identity/recovery boundaries and fault injection
are checked once against the frozen source. Each selected native target builds
the deliverable and exercises its installed OS process, including shared-project
configuration, original installed identity discovery, scoped IPC and ownership.
Additional library test groups can be requested with --library-tests; they are
recorded independently. An unchanged historical import or model/performance
campaign is not a default artifact-publication check. No Node producer is needed
for this native artifact workflow. Qualification reports explicitly distinguish
these scopes and do not infer semantic or performance evidence from a build.

## Native0.3.6 initial availability

Linux x86_64 GNU and Windows x86_64 are qualified for initial publication.
macOS ARM64 remains pending because no hosted runner was allocated; its0.3.6
build has not run and is not qualified. Consult the actual release for later
availability. No Mac success is inferred from Linux or Windows tests.
