# Windows protected-state fixture and CI failure propagation — 2026-10-13

This is a source and Linux regression checkpoint for the experimental Windows
x64 SDK. It does not establish a Windows build, package install, protected
filesystem behavior, or native Agent workflow on Windows or macOS.

Base source is `e1856a63299a2296186a133c534415c8ec530f6a` in isolated worktree
`peerwork-sdk-portability-20261013`. The first concrete blocker was test
setup in `crates/runtime/src/kernel_identity.rs`: three cross-platform
identity lifecycle/import tests used a raw `tempfile::tempdir()` parent. Unix
changed it to mode 0700; Windows did not give it the exact protected
current-user DACL required by `SecureStateStore::open ->
windows_fs::private_parent -> create_private_directory`. Consequently a
normal broadly inherited Windows temp DACL could refuse the test before it
exercised identity behavior. This is a fixture precondition, not a reason to
weaken the runtime DACL policy.

Commit `c3243f133ced39331e00224ecb805857ec9410da` changes only that test
file (SHA-256 `8104dd92e0fe9bdfa0791503ff2bfe1b300c30f6a1521cf3e2d88d5f270736a0`).
`ProtectedTestDir` retains the original tempdir for the test lifetime and
uses a nested `windows_fs::create_private_directory` path on Windows. Unix
continues to use a 0700 parent; source-file 0600 checks and all test
assertions remain. Luna reviewed the DACL/ownership precondition and found
no source issue.

Affected Linux command, using task-local Rust 1.89 and target directory:

```sh
CARGO_HOME=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-target/cargo-home \
CARGO_TARGET_DIR=/root/workdir/message/.worktrees/peerwork-sdk-portability-20261013/.build-target \
RUSTC=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/glibc28/bundle/rootfs/opt/rust/bin/rustc \
RUSTDOC=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/glibc28/bundle/rootfs/opt/rust/bin/rustdoc \
cargo test --offline --locked -p peerwork-runtime kernel_identity::tests:: -- --nocapture
```

The actual invocation also placed that Rust bin directory first on `PATH`
and set `LD_LIBRARY_PATH` to its `lib`. Session `63108` exited 0: all three
selected tests passed, zero failed, 112 filtered. `kernel-identity-linux.log`
SHA-256 is `ee7aada21d35660808df29759e3e002c5104169569446ddca38460090c15bc56`.
This is Linux regression only. The available Rust 1.89 rootfs toolchain lacks
the `x86_64-pc-windows-gnu` standard library, a MinGW C compiler, and
`pwsh`; no Windows-target compile or execution was performed in this lane.

A separate source-backed CI defect was in the Windows job of
`.github/workflows/distribution-spike.yml`: PowerShell does not turn each
failed native program into a terminating error merely because later cmdlets
run. Its early `cargo test/build`, maturin, npm, wheel verification/import,
and identity smoke could be followed by successful commands, masking the
original exit code; only mypy and dumpbin had immediate guards. Commit
`321cc58ff6c2f09b358d5b8800dad6be2179e529` changes only the workflow
(SHA-256 `c9b740823e18f8c55ec8f5c4ca6534939afc90affa56073afe4ff83847651bf6`).
It checks `$LASTEXITCODE` immediately after each native command, including
the `vswhere` command before `.Trim()`, and retains the original failure code.
A static source audit found 22 guarded Windows native boundaries;
`workflow-windows-native-exits.log` SHA-256 is
`698f70877abb7f7a31586b3b895f2ea6e0689505b22bc88dfeed891822498ed6`.
The workflow has not run on Windows, so actual PowerShell syntax/execution
and Windows package behavior remain unverified.

The macOS x64/arm64 and Windows x64 jobs still need real runner execution,
artifact dependency inspection, protected-path/locking tests, and installed
consumer behavior before platform support can be claimed. The accepted
Linux x64 glibc 2.28 artifacts were not touched or rebuilt for these
test/workflow source changes.
