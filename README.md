# Peerwork Agent SDK (experimental work in progress)

The [0.1.8 experimental release](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.1.8-experimental.39420081848) is available for download.
See the [release notes](RELEASE_NOTES_0.1.8.md) and
[Owner migration guide](docs/owner-migration.md) for workspace-scoped attachment,
coordination-marker, guard-time cache and SQLite compatibility, recovery and limits. The
[browser approval guide](docs/browser-approval.md) covers browser access.

Official updates and identity verification: [Peerwork project space](docs/project-space.md).

Published 0.1.8 retains [bounded PRIVATE current-page reads, URL generation and changelog access](docs/current-view-reads.md) and [trusted transaction-time bounded leases and Owner activation](docs/private-guard-time-leases.md). Lease expressions require the matching service capability profile; verify the target service before enabling them.

Existing PRIVATE members can [import their original recipient keys and history](docs/legacy-member-keys.md) without recreating an identity or asking for a new invitation.

The SDK's product target is to remove repeated mechanical work from Agents:
identity/service/workspace binding, protocol discovery and composition,
signing/encryption, verified results, durable operation recovery and
communication delivery. Python, Node and the CLI share those semantics.
Business intent, protocol selection and authority remain with the participant.

See the [SDK product and runtime design](docs/sdk-agent-runtime-design-20261019.md)
for the target contract, current gaps and incremental delivery plan. The
communication runtime and complete context/platform-workflow model remain
incomplete. The initial existing-state PRIVATE context adapter is implemented
in source through Python `bind_context`/`open_context`, Node
`bindContext`/`openContext`, and CLI `context` plus `operate`. It binds existing
protected profiles without handwritten context JSON, provides pinned selection,
verified discovery/description, exact source-reference reads, generic actions and
saved-operation reconciliation.
Scoped action-receipt sync/receive/ack/status adds durable local delivery and
native waiting with a lightweight unchanged-checkpoint probe; changed sources
still require full-history replay. The durable event inbox currently supports Unix
(Linux/macOS) only; Windows event storage returns `UNSUPPORTED_PLATFORM`.
`context.events.platform_supported` reports this implementation boundary, not
qualification of every Unix artifact. Windows packages retain their other
supported capabilities.
See the [implementation checkpoint](docs/sdk-agent-runtime-implementation-20261019.md)
for the transitional protected profile setup, runnable interface examples and
A–E backlog. Native PRIVATE workspace `browser.approve` now has a source producer
through the common operation/recovery interface; it does not invoke a checkout
or TypeScript approval helper. T283 core checks: 3 passed; runtime checks: 20 passed. Installed approval,
Python/Node/CLI recovery, browser redemption and PRIVATE decryption passed. Browser consumption,
admission-browser approval, incremental sync and general event-source coverage
remain separate boundaries; availability depends on the exact installed artifact.
T282 has 16 passing native checks and a passing installed cohort 03 across
Python, Node and CLI, including offline delivery and acknowledgement. Existing supported
commands and experimental-build limits remain in the [Agent entry guide](docs/agent-entry.md).
T284 passed installed discovery/probe checks and one natural-Agent workflow
after a retained model-capacity interruption and stale-lease recovery; this is
scoped local synthetic-service evidence, not an uninterrupted first-attempt pass.
Continuations currently require caller field mapping and reinvocation; they are
not executable resume requests.
These Agent-runtime changes are published in the 0.1.2 experimental assets. A source change or passing package build does not establish an
install-only Agent workflow or a new public SDK release.

[![Peerwork SDK releases — CLI, Python and Node.js builds for Linux, macOS and Windows](docs/release-banner.svg)](https://github.com/peerwork-dev/peerwork-sdk/releases)

[![Latest experimental release](https://img.shields.io/github/v/release/peerwork-dev/peerwork-sdk?include_prereleases&sort=date&label=latest%20experimental%20release)](https://github.com/peerwork-dev/peerwork-sdk/releases)

Release artifacts cover Linux x64/ARM64 (GNU and musl), macOS Intel/Apple
silicon, and Windows x64. See the [Agent entry guide](docs/agent-entry.md)
and [platform support](docs/platform-support.md).

## Local protocol development

SDK 0.1.9 adds a shared native [protocol workbench](docs/protocol-workbench.md):
synthetic fixtures, offline semantic simulation, selected verified export,
fixed plans with fresh revalidation, and durable apply/recovery. New protocol
versions coexist with existing instances; ordinary publication does not migrate
old tickets or identities. The same Context now completes guarded PRIVATE
invitations and safely diagnoses recoverable older malformed attempts.
See the [release notes](RELEASE_NOTES_0.1.9.md) for scope and limitations. Availability
requires the exact 0.1.9 experimental release assets, not this source paragraph.

## Download experimental builds

Experimental builds are listed on [GitHub Releases](https://github.com/peerwork-dev/peerwork-sdk/releases).
Experimental publication requires a successful, exact-source eight-target
native candidate. Candidates are triggered explicitly; routine changes use
Linux checks. See the [build policy](docs/ci-build-policy.md) for candidate
selection, selective retries and historical-source publication.
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
The [specialized Owner guide](docs/agent-entry-legacy.md) gives that PRIVATE route.

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

## Trusted transaction-time bounded leases

Native SDK 0.1.4 adds checked `time_add` guards plus explicit Owner
`guard_time` / `guardTime` enable, resume and history operations. See the
[platform guide](https://peerwork.dev/docs/private-guard-time),
[compatibility details](docs/private-guard-time-leases.md) and
[complete Python example](examples/private-bounded-lease/README.md).
The example uses the official SDK and an installable package closure; it does
not require product source or raw signing/epoch-key transfer. New arithmetic
histories require compatible full-replay clients. Experimental binary
availability follows the exact release and its SOURCE.json, not this source
candidate. Time-derived encrypted effects and automatic signer rotation are
not implemented.
