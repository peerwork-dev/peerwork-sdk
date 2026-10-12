# Peerwork native SDK (experimental work in progress)

This repository is a migration toward one Rust core with a native CLI, Python
binding, and Node-API binding. Version `0.0.1` is a **distribution and
compatibility probe**. It is not a complete Peerwork SDK and does not yet
support verified workspace reads, safe actions, durable recovery, or store
migration. Do not use these artifacts to make production decisions or publish
them as a complete verifier.

The baseline for migration is the accepted TypeScript SDK source at Peerwork
protocols commit `dd8a9d2`, with reviewed evidence commit `4065739`. The Rust
implementation must meet the protocol and differential conformance gates
before replacing that baseline. See [provenance](docs/provenance.md).

The three entrypoints call `peerwork-core` for their version and capability
manifest. `peerwork version` and `peerwork capabilities` print JSON. Python provides
`peerwork.version()` and `peerwork.capabilities()`. Node provides `version()` and
`capabilities()`. These calls do not enroll an identity, read a workspace, or
alter service state.

## Build the experimental artifacts

Use Rust/Cargo, Python 3.11 with maturin, and Node 24 at build time:

```sh
cargo test --workspace --locked
cargo build --release --locked -p peerwork-cli -p peerwork-node-native
cd bindings/python
maturin build --release --locked --out ../../dist/wheels
```

Node platform packages are built from the target-specific shared library with
`node bindings/node/scripts/package-platform.mjs TARGET LIBRARY dist`. No npm
install hook compiles or downloads code. A missing exact-version platform
package raises an import error. Python wheels contain the native extension;
the CLI is an ordinary executable. Consumers of prebuilt artifacts do not need
a compiler, but only tested targets will be declared supported.

Current validation and target gaps are tracked in
[platform support](docs/platform-support.md). Public packages and a production
release remain gated by protocol parity, recovery, target runs, and Agent
acceptance.

Licensed under Apache-2.0. See [LICENSE](LICENSE).
