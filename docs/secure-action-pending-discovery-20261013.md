# Protected PUBLIC action pending discovery, 2026-10-13

The protected local pending-list seam is `564e923`; its seven-field rows are
`command_id`, `actor_id`, `origin`, `workspace_id`, `action_id`,
`request_sha256`, and `commit_hash`. It does not expose packet bytes, keys or
receipts, and a listed row is not an accepted effect. The first runtime
regression found the initial borrowed replay path still opened network
discovery (`Read(Discovery)` after service shutdown). The corrected runtime
opens protected profile, identity, lifecycle and action-intent state locally;
its offline focused test passed 1/1 at the committed seam.

Python `SecurePublicActionClient.pending()/pending_async()`, Node session
`pending({signal})`, and CLI `secure action-pending CONFIG_JSON_FILE` were
committed in `020dfb2602d854040d9a95ecb1cbcd4e000f4e3e` with README
cancellation guidance. Rust 1.89 offline locked affected check of runtime,
CLI, Python native and Node native passed. Python `py_compile`, pinned Node
24.20 syntax, rustfmt, `git diff --check`, and a strict TS 7.0.2 declaration
check passed. This is local recovery of an unreturned command ID; only
subsequent signed replay can accept the command.

The exact `020dfb2` detached source and lock SHA-256
`9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`
were built with Rust/cargo 1.89.0 offline locked, maturin 1.15.0, Python
3.11.15 and Node 24.20.0. The installed Python wheel
`peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl` SHA-256 is
`7a4abbd4d621ce409b0a3202048adcc0f58a440a47db2fbe5e21ff5e2d57cbe0`;
offline npm facade and GNU platform tarballs SHA-256 are respectively
`19c2b90026333f90e6f766c5558931e52c9086f805f9209e6dc2506c99dad8c9`
and `28a9933f0219e46f8ea3ed6a140674e9bd07292c294bb509d6abc302e610f647`.
The CLI SHA-256 is
`54a2008d6590c5cc0e5243ceb840d12279b9a78b467298196ee73b9947ab0156`.
Fresh offline Python target and Node optional-package installs imported from
their installed paths. The first npm pack attempt failed because the default
`/root/.npm` cache was read-only (`EROFS`); rerunning with an ignored
task-local npm cache passed. Build sessions `52155` (wheel) and `23536`
(CLI/addon) both terminated with exit 0.

The first `020dfb2` smoke source cancelled a coroutine before it started;
that established only unstarted-task behavior. Test-only commit
`f1adac72601214a40b029b6a1178f68a134481f8` corrected the pre-persist
case to delay a real journal GET, observe the in-flight request, then cancel.
The corrected test SHA-256 is
`a3e398126ebf5204a55d423761f5dc2d5df7baf6cba1b16e5b37e9264398693a`;
the test-only reference bridge SHA-256 is
`f85c4416752ff31a62d1328749a00122b9e363822dcae1a7a17e9aa617399bfe`.
The bridge guarded the tracked TS checkout at
`f828b6c50a0a58d1e718af90f653b214adcc3328` and its exact compiled
source closure. The SDK artifacts remained built from immutable `020dfb2`;
the test correction did not change production source.

The first installed smoke launch failed before service startup because the
sandbox denied fixture `spawnSync git` (`EPERM`); the authorized local-socket
retry, session `59550`, exited 0. On fresh synthetic state, cancellation
after the observed pre-submit journal GET left **zero** pending rows and the
service at one bootstrap commit. In the second attempt, the service applied
the action and held its reply; Python task cancellation drained native work
and returned no generated ID. A fresh Python client, Node installed package
and CLI independently returned the same one protected pending row. The
bridge's journal GET counter did not advance during any listing. Python then
reconciled that exact ID against signed replay: `ACCEPTED`, sequence 2, one
effect, still two service commits, and no pending rows. The owned fixture
service was terminated in the test's `finally` block. These observations
establish the installed business/recovery path for this synthetic PUBLIC
action on Linux x64; they do not establish broader platform coverage or
Agent workflow compliance. No Agent instruction/tool-call trace was
collected, so workflow compliance is **unverified**.
