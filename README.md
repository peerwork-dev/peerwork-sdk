# Peerwork native SDK (experimental work in progress)

## Download experimental builds

Experimental builds are listed on [GitHub Releases](https://github.com/peerwork-dev/peerwork-sdk/releases).
Automatic prerelease publication is configured, but the initial publication
is blocked because GitHub rejected release creation for the historical build
target. Until then, download
verified build artifacts from the [native distribution workflow](https://github.com/peerwork-dev/peerwork-sdk/actions/workflows/distribution-spike.yml).
Prereleases are experimental; they are not stable releases and do not publish
packages to PyPI or npm. A workflow targeting a commit whose workflow files
differ from the default branch requires a credential with Workflows permission
for release creation ([GitHub documentation](https://docs.github.com/en/rest/releases/releases#create-a-release)).

For Agent integration, start with the [Agent entry guide](docs/agent-entry.md)
and see [platform support](docs/platform-support.md) for target details.

This repository is a migration toward one Rust core with a native CLI, Python
binding, and Node-API binding. The initial version `0.0.1` was an **experimental compatibility
probe**. It supports protected local identity, configured-origin kernel
discovery, signed command preparation, a durable intent journal, receipt-bound
kernel status/results, and exact saved-command retry. A guarded import path
for the tracked TypeScript kernel-intent store has focused migration tests.
Verified secure-agent reads/actions, full result models, and cross-platform
release acceptance remain incomplete. Do not use these artifacts as a
production Agent SDK or publish them as a complete verifier. This whole-SDK readiness
limit does not disable the bounded native Owner PRIVATE create, signed read,
explicit direct/staged install, action and saved-command recovery routes.
Their command contracts and focused real-service evidence apply within the
specified identity/source/authorization scope; broad capability flags remain
conservative and do not promise complete coverage. For a selected local package,
run `peerwork secure owner-private-install-begin-direct --help` or
`peerwork secure owner-private-stage-submit --help`: compiler material is not an
install envelope or a grant. PRIVATE pending/status/retry commands carry the
`owner-private-` prefix; `owner-install-*` and `owner-action-*` are PUBLIC routes.
The [Agent entry](docs/agent-entry.md) gives the complete PRIVATE route.

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

### Protected configuration

Protected configuration discovery is opt-in and read-only: Python `config = peerwork.load_config()` then `peerwork.SecureOwnerWorkspaceClient(**config)`; Node `sdk.openSecureOwnerWorkspaces(await sdk.loadConfig())`; CLI `peerwork config resolve [PATH]` prints the same public configuration with `state_dir`. Existing explicit constructors and CLI JSON-file arguments bypass discovery unchanged.

Selection is explicit helper path, then `PEERWORK_CONFIG`, then Linux `$XDG_CONFIG_HOME/peerwork/config.json` (or `$HOME/.config/peerwork/config.json` when XDG is unset), macOS `$HOME/Library/Application Support/peerwork/config.json`, or Windows `%APPDATA%/peerwork/config.json`. The selected file must contain only `{"origin":"https://control.example","state_dir":"state"}`. Node returns `{origin, stateDir}`. Relative state paths resolve against the config file directory, never the working directory; parent traversal is rejected by protected path rules. Explicit file paths and `PEERWORK_CONFIG` may be relative to the current directory. OS location roots must be absolute. An empty selected environment value, missing/unsafe file, unknown/duplicate field, or invalid origin fails closed with a `CONFIG_*` code; no fallback occurs after selection.

The config is bounded to 16 KiB, must be an owner-protected regular file without symlinks/hardlinks, and its directory and existing state directory (or immediate parent for new state) must meet the native protected-directory rules. On Unix use private directories and mode 0600 or stricter files; read-only private config directories/files are supported. The resolver creates no directories, locks, identity, authority defaults or network requests and never reads identity state. HTTPS origins cannot contain credentials, non-root paths, query or fragment. Loopback HTTP remains available only through the existing explicitly configured constructors, with their explicit opt-in; discovery adds no bypass flag. macOS/Windows selection conventions are source-defined, with execution pending platform gates.
