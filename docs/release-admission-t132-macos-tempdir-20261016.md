# T132 macOS CI diagnosis and candidate

On run `38856001214` at source SHA
`87b6d2e8f2fecf0582d3f799df8c5abbe26586d5`, both macOS jobs failed during
`cargo test --workspace --locked`: Intel job `116827488821` and ARM64 job
`116827488837` each reported 127 passed, 58 failed and 4 ignored. The first
shared failure is `kernel_intents::tests::child_prepare_worker` returning
`Protection`; many secure-state tests fail the same guard, with some secondary
error-classification assertions. Logs are retained at
`/tmp/t132-sdk-macos-diagnosis-20261016/job-116827488821.log` and
`/tmp/t132-sdk-macos-diagnosis-20261016/job-116827488837.log` (fetch metadata:
`/tmp/t132-sdk-macos-diagnosis-20261016/fetch-result.json`).

The Unix private-parent guard in `crates/runtime/src/secure_state.rs` requires
`fs::canonicalize(parent) == parent`. Workspace tests create protected
fixtures from `tempfile::tempdir()` but do not canonicalize their returned
paths. The macOS workflow did not set `TMPDIR`; its later identity smoke does
resolve `RUNNER_TEMP` with `pwd -P` before using that path. This makes an
OS temporary-path alias a plausible common cause, but the failed runners did
not log their original temp paths, so the cause remains an inference.

The macOS workflow now exports the physical `RUNNER_TEMP` path as `TMPDIR`
before its workspace test/build and logs the selected temp base. This keeps
the production path and symlink checks and all test assertions unchanged. The
ARM64 rerun on candidate SHA `9eb94aeadc4cb41c8f1e0be7ea5ec64a9ff4b3c2`
confirmed the test-path change: the workspace suite passed 185 tests with 0
failures and 4 ignored. The next `cargo build --release` failed while linking
`peerwork-node-native` because the macOS linker reported undefined `_napi_*`
symbols; the CLI, Python and Node installed-consumer checks were not reached.
That log is retained at `/tmp/t132-sdk-macos-push-20261016/job-116842776350.log`.

The Node native crate is a `cdylib` using `napi 2.16.17` without its
`dyn-symbols` feature. On non-Windows targets the pinned `napi-sys 2.4.0`
declares Node-API as external symbols. This candidate adds a build script only
to that crate, gated to macOS, and emits Cargo's cdylib-only
`-Wl,-undefined,dynamic_lookup` argument so Node-API imports can resolve from
the host at load time. It adds no global linker flags or dependency and does
not affect CLI/Python links. Cargo documents the cdylib-only build-script
directive at <https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-arg-cdylib>.
The macOS addon load/import smoke must still pass on both architectures before
this linker change is accepted as working; no result is claimed yet.
