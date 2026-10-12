# Real tracked kernel HTTP checkpoint, 2026-10-12

The opt-in runtime integration test runs the tracked TypeScript Peerwork
`WorkspaceKernel` and `createWorkspaceControlApp` on fresh private temporary
SQLite state. It uses Node 24.20.0 and the built integration checkout at
`f828b6c50a0a58d1e718af90f653b214adcc3328`. Relevant tracked SHA-256
files: `src/workspace-kernel.ts`
`586ac5b6a689abd2782d5d3e093bdf2ebc3eaaa688b526908b0402fb7783b4e2`,
`src/workspace-http.ts`
`4e8ab5d5484120395f28e39d2a703804328563efacfe90dfe9b761f923236355`,
`package-lock.json`
`80d6ed0f40c4dbfa180289aad67054a35b25843754291ae7a34780c81f77a51f`.
The reference checkout was rebuilt with `npm run build:workspace` before the
test. The test bridge checks the exact checkout commit; clean tracked `src`,
`tests`, `scripts`, TypeScript configs, package manifest and lockfile; no
untracked code/JSON under those source directories; the three source/lock
hashes above; compiler version 7.0.2; and that the compiled entrypoints are
newer than their tracked TypeScript sources. It also hashes all 204 compiled
`dist-workspace/src/*.js` files by relative name and bytes; the tested build
closure digest is
`6de57ae9bbaae615c0d7f87e744e5422dfc25959bf92a659c28c924961ddf1dc`.
This is a real service handler over HTTP,
not a synthetic receipt server.

The development proxy awaits the real handler's first signed `workspace.create`
response, then drops that client connection. The native client reports the
submitted result uncertain and leaves its exact saved command pending. The
test checks the service already contains one command and one workspace before
retry. After native journal restart, retrying the exact saved ID obtains a
verified signed receipt and redacted result. A second native client with its
own journal submits the same signed ID and gets the same accepted summary;
the service still contains one command and one workspace. A differently
signed body with that command ID receives HTTP 409 from the real service.
This confirms the pinned service's same-ID dedup and digest conflict path for
this command. Two different signed `protocol.publish` IDs then target the
same workspace at revision 1: the first returns HTTP 201, the second HTTP 409,
and the service has exactly one protocol with workspace revision 2. This
establishes one stale-revision conflict path, not every business action.

`KernelAcceptedResult` now exposes only authenticated command, workspace,
protocol, instance, event, revision and produced-record identifiers. Signed
packets, arbitrary result JSON and private state are kept internal. This is
an audited summary, not yet the complete typed proposal/adoption/task result
surface or Python/Node/CLI binding behavior.

The next local identity checkpoint creates an Ed25519 seed only on explicit
`KernelIdentity::create`, using the OS random source and a protected native
state path. `open` rejects missing, malformed or old-format state without
rewriting it; public methods expose only key and actor IDs. Temporary seed,
decoded seed, encoded seed and saved wire buffers use zeroizing wrappers.
The identity parser checks its fixed canonical byte layout without creating
another decoded JSON copy of the seed; OS entropy failure is a typed error.
The core's `prepare_signed_command_wire` validates the tracked command
schema, signs and self-verifies exact bytes; runtime `prepare_command`
persists its JWS/body before transport. The real-service recovery test now
uses this identity and signing path for the first command. Linux focused
identity and real-service tests passed; Windows file protection and runtime
behavior still require the actual Windows runner.

The first opt-in attempt failed before the service started because the test
bridge passed an Ed25519 private-key object where `WorkspaceKernel` requires
a receipt seed `Buffer`; the bridge was corrected. The real HTTP test then
passed. The regular runtime suite passed 27 tests with this opt-in test
ignored. The local socket tests require the approved localhost execution
route because the default sandbox denies binding 127.0.0.1; an earlier default
run failed with `EPERM`, then passed through that route.

Run from the SDK worktree after building the reference checkout, with the
task-local Rust 1.89 `RUSTC`, `RUSTDOC` and `CARGO_TARGET_DIR` set:

```sh
PEERWORK_REFERENCE_ROOT=/absolute/pinned/integration-checkout \
PEERWORK_TEST_NODE=/absolute/node-v24.20.0/bin/node \
cargo test -p peerwork-runtime real_reference_kernel_recovers --offline --locked -- --ignored
```

## Configured kernel facade checkpoint

`KernelAccess` now carries the configured origin, identity path, intent
journal path, required features and optional authority digest. Its default
authority is SHA-256 of the local actor ID, matching `WorkspaceClient`; a
fully specified command is refused before signing unless its authority
matches the configured value. The core separately checks the command actor
against the local signing key and audience against discovery. Every facade
operation reopens discovery over the configured origin, checks persisted
continuity, and reopens the protected identity. `prepare` signs and saves the
exact request without POST; `submit_saved` sends only a saved command and
returns receipt-verified redacted fields. `status` and `pending` recheck saved
proofs after restart. No JWS, raw result JSON or private key is returned.

The actual tracked-service test was extended to reopen through this facade,
check accepted status and idempotent accepted `submit_saved`, prepare a new
unsent command and observe `PENDING`, then reject a mismatched authority.
With Rust 1.89, `cargo check -p peerwork-runtime -p peerwork-cli
-p peerwork-python-native -p peerwork-node-native --offline --locked` passed,
and the opt-in real service test passed 1/1. Python, Node and CLI source
wrappers now call this same boundary, but this checkpoint does not yet claim
installed wrapper end-to-end service execution. At this checkpoint their async
work could outlive an abandoned Python await or Node Promise; the later
cancellation checkpoint below adds native request tokens. Submitted uncertainty leaves a saved pending row for
status/retry, while a newly prepared row has not been submitted. Verified
secure-agent reads/actions, complete typed result models, and the real
macOS/Windows runner gates remain open.

## Installed Python, Node and CLI service path

An isolated detached checkout at exact commit `321ee1f` built the Python
wheel, Node addon and CLI with Rust 1.89 and `--offline --locked`; the wheel
was installed from its local binary with `pip --no-index --no-deps`. The
Linux artifact SHA-256 values were `74ca708e4b1ec28d14f10c84525deaf3b635dfbd28adf6194a324fc2ed5a5b57`
for `peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl`,
`a3da157dd3beb3a51f83613ae362b4ed5552ebce5adfbfd276f566964acb7cab`
for the optional Node `index.node`, and
`9b0da2184d2aecd139e44b3d0dd85993914478b40846cbd64347fc532c6e8ea5`
for the CLI `peerwork` binary. These are development artifacts, not release
packages or declared minimum-platform binaries.

With fresh synthetic state and the tracked actual Peerwork kernel bridge,
the installed Python binding rejected a mismatched configured authority
before preparing a row, saved a valid command as `PENDING`, then observed a
POST that the server committed before its reply was dropped. It retained
`PENDING` and an exact saved retry produced a verified `ACCEPTED` result.
The installed Node binding reopened the same identity and journal, read that
accepted result and retried it without another POST, then prepared and
submitted a second valid command. CLI reopened the same journal and read
`ACCEPTED`; service counts were exactly two commands and two workspaces.
Observed monotonic stages from installed Python import were: discovery pin
393 ms, first saved command 501 ms, post-commit lost reply 741 ms, first
verified result 888 ms, Node cross-language result 1406 ms, and CLI status
1475 ms. These are one run's observations, not performance commitments.
This script demonstrates business-path behavior; it is not an Agent usability
run, so Agent workflow compliance remains unverified.

The first public facade checkpoint did not pass catalog chunk bytes through
the Python, Node or CLI wrappers, although the core/runtime could validate
them. The follow-up binding change adds Python `bytes`, Node `Buffer` or
`Uint8Array`, and CLI `--chunk-file`/`--chunk-stdin` for `prepare`. The shared
core retains the 1–65,536-byte bound and signed chunk digest check. Node
command objects also undergo strict JSON-data inspection before stringify;
this closes `NaN`→`null` and omitted `undefined` member coercions. These
follow-up paths require an affected installed-interface regression before
claiming end-to-end catalog upload support.
The Node wrapper also rejects Proxy values and serializes a snapshot built
from inspected own data-property descriptors, with null prototypes. That
prevents a Proxy getter or inherited `toJSON` from changing values between
inspection and serialization.

An isolated, locked offline rebuild at exact correction commit `94c547f`
produced Linux wheel SHA-256
`4fea4a8c9e09d95121f39dc05c774e278ea5077073c4a69eac6e4b0e634c5d19`,
Node addon SHA-256
`45a7df29702a8f459564f4e8f647f440090c013904bd01ee4a5c5b98147ce30a`,
and CLI SHA-256
`f9b326ae2478a02b81dbd085994d1625cce6ba1dc74e717186df50a1f97524b6`.
The wheel was installed from its binary with `--no-index --no-deps` into a
fresh target. A fresh synthetic actual-service run passed the same Python
post-commit lost reply and exact retry, Node same-journal accepted reuse and
second submitted workspace, and CLI accepted status. It additionally
prepared catalog chunk commands through Python async `bytes`, Node `Buffer`
and `Uint8Array`, and CLI file and stdin. A mismatched chunk digest was
refused before saving a row. Node rejected `NaN`, an undefined extra member
and a Proxy getter, and an inherited `toJSON` could not alter the signed
command. Catalog preparation did no POST; actual service counts remained two
commands and two workspaces. This proves binary entrypoint preparation, not
catalog service acceptance. Observed stages from installed import in this
single scripted run: discovery pin 368 ms, first command saved 465 ms,
post-commit lost reply 628 ms, first verified result 759 ms, Python chunk
saved 1064 ms, Node cross-language result 1830 ms, CLI status 1898 ms, CLI
chunk saved 2017 ms. Agent workflow compliance remains unverified.

## Installed in-flight cancellation and recovery

An isolated checkout at exact commit `d5e4aaf` rebuilt the Python wheel,
Node addon and CLI using Rust 1.89 with the locked offline dependency graph.
The wheel was installed as a prebuilt artifact using `pip --no-index
--no-deps`. SHA-256 values: wheel
`277bc02943203d2598b2cfdce435b3206ffc52767afa4b3c1ab0a8ca5ba245ed`,
Node `index.node`
`579cddbab1bf1afa6b87e383b199ae865ba4a1d867fc5f96f7847dd7447e9a80`,
and CLI `peerwork`
`31f0cf708687f21687cfa9f77a3a5431c3b44e8ea7bd81b1ea9adc07b085684b`.
These development artifacts are Linux x64 only; the wheel's measured tag is
`manylinux_2_38_x86_64`, not a frozen minimum compatibility target.

The test used three fresh synthetic stores and the tracked actual Peerwork
kernel HTTP app. For each installed entrypoint, the service committed the
first POST, then delayed its reply for five seconds. Python cancelled its
async task, Node aborted its signal, and the Unix CLI received SIGINT while
that reply was outstanding. The Python worker drained before cancellation was
reported; the CLI exited 130. Each journal still showed `PENDING`, and exact
saved-command retry returned a receipt-verified `ACCEPTED` result with one
server command. The first pass exited zero without retrying failed samples.
The reusable source is
[`tests/installed-cancellation-smoke.py`](../tests/installed-cancellation-smoke.py);
it requires a previously built reference checkout and installed local
artifacts, and writes only a sanitized task-local JSON evidence file.
Observed stages from installed Python import were Python cancellation 527 ms,
Python accepted retry 654 ms, Node abort/retry 1490 ms, and CLI interrupt/retry
2303 ms. These are one synthetic run's elapsed times, not latency guarantees.
It is business-path evidence; Agent workflow compliance remains unverified.

To reproduce from an exact SDK checkout, build/install the wheel, Node addon
and CLI, place `index.cjs` and its exact platform `index.node` under
`.build-artifacts/node-consumer`, then run with a Python path pointing at the
installed wheel target:

```sh
PEERWORK_REFERENCE_ROOT=/absolute/pinned/built-reference-checkout \
PEERWORK_TEST_NODE=/absolute/node-v24.20.0/bin/node \
PEERWORK_TEST_WHEEL=/absolute/peerwork-sdk-wheel.whl \
PEERWORK_TEST_NODE_ADDON=/absolute/index.node \
PEERWORK_TEST_CLI=/absolute/peerwork \
PEERWORK_TEST_SOURCE_COMMIT=d5e4aaf \
PYTHONPATH=/absolute/installed-wheel-target \
python3 tests/installed-cancellation-smoke.py
```

This covers an already submitted HTTP request. Local identity creation can
finish after its caller abandons the await; its documented reopen behavior
still needs a bounded executable lifecycle regression. Windows console
interruption source was added later; its actual delivery and recovery, and
the full Windows/macOS runner execution gates, remain open.

Reviewer follow-up found that a second Python task cancellation could escape
the worker-drain await, and two simultaneous Unix CLI monitors could replace
each other's process-global handlers. Commit `18499546d4daa09d219d979ae6f9a8e48d0a781d`
keeps draining across repeated cancellation and permits one signal-handler
owner at a time. The focused runtime singleton test passed 1/1 under Rust
1.89. The installed regression adds a deterministic twice-cancelled slow
Python worker and asserts that cancellation is reported only after it exits.
Its first pinned run stopped before service startup because the harness was
given an incorrect commit hash; using the exact checked-out hash, the
installed wheel/addon/CLI and real-service regression passed on its first
service run. SHA-256 values for that corrected source pin were wheel
`501685f495700bedc45b2e85617f2c44a59c56cd8506185ea79dc5dba0f929ba`,
Node addon
`51dba76c59c8e77f44da57664db248108ae1a8e755105b0e7313dcd9ddc2a64e`,
and CLI
`06000f9946414963c87c2ac5eb788ad44749d7fb349fa10164cb6ee76fe70bca`.
Observed stages from installed import: repeated-cancel worker drain 2 ms,
Python in-flight cancel 515 ms, Python exact retry 826 ms, Node abort/retry
1695 ms, CLI interrupt/retry 2482 ms. Each service had one command and one
workspace after recovery. Cancellation during local preparation can still
race with durable insertion of a new `PENDING` row; callers inspect
`pending()`/`status(command_id)` before attempting another prepare. This
scripted run does not establish Agent workflow compliance.

## Installed catalog upload and publication

At exact SDK source commit `632bd159830eddfb4f20f9d0de39ffed330d8cfb`,
an isolated Rust 1.89 locked-offline build produced a Python wheel (SHA-256
`fdd86fcb3fea6bed83b39f60b29a1884d7d09097431e812716104324ee508403`),
Node `index.node` (SHA-256
`89450c1c82c69b0e354f737dcb86e85384748c6b19dc623ac686e8eb568fa2ec`),
and CLI (SHA-256
`346c0cdf1a31dd077c3b764fdab843fb96801af9fa04a0aa82477cf86c62b6a7`).
The wheel was installed with `pip --no-index --no-deps`. These are measured
Linux x64 development artifacts, not release packages or a minimum platform
claim.

The opt-in [installed catalog regression](../tests/installed-catalog-smoke.py)
used fresh synthetic protected identity/journal/service state, the tracked
Peerwork kernel HTTP app, and the tracked protocol-package parser/compiler
adapter from the official catalog publish fixture. The official
`protocols/proposal-adoption` bundle was canonicalized by the tracked
TypeScript package code: 24,804 bytes, SHA-256
`a7b9713067524ab85e988be2e665998e15a42c813c60e0a92880afec32b5c95c`.
The installed Python SDK registered the identity, claimed its namespace,
began the upload, sent the one binary chunk, and published the package.
Before the valid chunk, a payload whose bytes differed from its signed digest
was refused before a saved row or POST. The final receipt-verified public
catalog result matched the exact signed namespace, package ID, version and
bundle digest; no raw JWS, private key, or source bundle was returned.
Reopening the saved publish returned the same accepted result in Python,
Node, and CLI. The service counted five commands, one namespace, one consumed
upload, zero staged chunks, one package and one outbox entry; an accepted
same-ID retry did not create another package or outbox entry.

Observed stages from installed Python import were official bundle
canonicalization 168 ms, namespace claim 1080 ms, upload begin 1312 ms,
wrong-chunk refusal 1411 ms, verified binary chunk 1686 ms, verified
publication 1922 ms, accepted retry 2063 ms, and Node/CLI recovered status
2402 ms. These are one scripted synthetic run's elapsed times. The existing
runtime suite initially had one failure: its signed namespace receipt fixture
contained no namespace/owner fields, which the new semantic result binding
correctly refused. Its fixture was corrected to the tracked server shape and
the focused lost-reply/invalid-receipt regression passed; the other 28 tests
had passed in that initial suite. This business-path test does not establish
Agent workflow compliance, multi-chunk upload behavior, or macOS/Windows
execution.

To reproduce from a pinned SDK checkout after building the pinned reference
checkout and installing the locally built wheel/Node addon/CLI, use the
same artifact environment variables as the cancellation regression above
with `PEERWORK_TEST_SOURCE_COMMIT=632bd159830eddfb4f20f9d0de39ffed330d8cfb`,
then run `python3 tests/installed-catalog-smoke.py`. The script asserts its
source pin before touching service state and writes only sanitized task-local
counts, hashes, and stages to `.build-artifacts/catalog-service-evidence.json`.
