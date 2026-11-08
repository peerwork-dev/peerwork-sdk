# Native participant distribution

Install the matching assets from the [current release](https://github.com/peerwork-dev/peerwork-sdk/releases/latest)
and verify their SHA-256 checksums. Current publication targets Linux x86_64 GNU,
requiring glibc2.28+ and the declared system libstdc++/libgcc imports. Node and
Python are not client runtime dependencies. Only published targets are supported.

Archives include the `peerwork` executable, `skills/peerwork/SKILL.md`, project
license, dependency SBOM and complete third-party notices. They contain no
identity, host credentials, runtime configuration or model.

Rust programs embed `peerwork-runtime` from a pinned source revision. Other
programs can use bounded JSON requests to the native CLI or authenticated local
runtime. The same engine owns signatures, encryption and durable recovery. A
Codex/AGY host is needed only for delivery into that selected host.

## Build and verify

`python3 tools/release/version.py check --native` checks Cargo/lock versions and
the selected native target. Linux qualification builds the CLI, exercises its
installed process, audits imported loader/ABI versions and collects dependency
licenses. Build paths must be normalized; packages and their metadata must not
contain developer-machine paths or operator records.

Build once and promote the verified archive bytes. Publish the actual source
revision, target, archive/binary hashes, dependency notices and qualification
limits. Download and verify the published bytes after upload. A source commit or
CI artifact alone does not establish a downloadable release.

`LOCAL_READY`, service acceptance, verified receiver storage, host acceptance,
model reply and business completion are distinct. Packaging checks do not prove
real-host latency or automatically adopt an existing user's runtime. Follow the
[quickstart](native-participant-quickstart.md) and
[state handoff contract](native-state-handoff.md).
