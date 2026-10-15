# Peerwork native SDK (experimental work in progress)

This repository is a migration toward one Rust core with a native CLI, Python
binding, and Node-API binding. Version `0.0.1` is an **experimental compatibility
probe**. It supports protected local identity, configured-origin kernel
discovery, signed command preparation, a durable intent journal, receipt-bound
kernel status/results, and exact saved-command retry. A guarded import path
for the tracked TypeScript kernel-intent store has focused migration tests.
Verified secure-agent reads/actions, full result models, and cross-platform
release acceptance remain incomplete. Do not use these artifacts as a
production Agent SDK or publish them as a complete verifier.

The baseline for migration is the locally tracked TypeScript SDK source at
Peerwork protocols commit `dd8a9d2`, with reviewed evidence commit `4065739`.
That commit is not retrievable from the public origin; the attributable
[reference closure](conformance/reference/NOTICE.md) is vendored for portable
differential tests. The Rust implementation must meet the remaining protocol
and acceptance gates before replacing the baseline. See
[provenance](docs/provenance.md).

The three entrypoints call `peerwork-core` for their version and capability
manifest. `peerwork version` and `peerwork capabilities` print JSON. Python
provides `peerwork.version()` and `peerwork.capabilities()`; Node provides
`version()` and `capabilities()`. These introspection calls do not alter service
state. Python `KernelClient`, Node `openKernel()`, and the CLI kernel commands
use the configured origin and protected identity for prepare/status/retry.
Cancellation of an in-flight POST retains uncertain saved state for recovery;
see the [real-service evidence](docs/runtime-real-kernel-20261012.md).

For an operator-installed local Agent trial, start with the [Agent entry
guide](docs/agent-entry.md). It describes explicit identity, workspace and
source selection and exact-ID recovery; it is not a public installation guide.

The selected partial object-stage CLI routes are `secure owner-object-stage-inspect
CONFIG INPUT ORIGINAL_STAGE_COMMAND_ID OPTIONS MATERIAL`,
`secure owner-object-stage-attach CONFIG INPUT ORIGINAL_STAGE_COMMAND_ID
INSPECTED_TS_STATE_DIGEST OPTIONS MATERIAL`, and `secure owner-object-stage-recover
CONFIG ATTACH_ID ORIGINAL_STAGE_COMMAND_ID` (all CONFIG/INPUT/OPTIONS/MATERIAL
arguments are JSON file paths). Inspect/attach submit no command. Explicit
recovery reconciles the original final stage and authorizes a distinct saved
native installation BEGIN; keep the original stage ID for later recovery.
`ATTACHED_RESTRICTED` remains unresolved until signed END yields `ATTACHED`.

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
