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
test. The test bridge checks the exact checkout commit, clean tracked `src`
and lockfile content, no untracked `src` files, the three source/lock hashes
above and that the compiled entrypoints are newer than their tracked
TypeScript sources before launching. This is a real service handler over HTTP,
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
