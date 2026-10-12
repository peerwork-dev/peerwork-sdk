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
installed wrapper end-to-end service execution. Their async work can outlive
an abandoned Python await or Node Promise; there is no exposed in-flight
cancel handle yet. Submitted uncertainty leaves a saved pending row for
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
