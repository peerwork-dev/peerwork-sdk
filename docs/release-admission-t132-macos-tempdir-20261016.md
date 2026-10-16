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
change has only diff/whitespace validation so far; hosted macOS results are
required to confirm or reject the inference. No macOS artifact or runtime
acceptance is claimed.
