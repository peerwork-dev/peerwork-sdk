# Owner-create CLI help regression

At `43ac40d910cb679b417c95136c8140ca468bf447`, `secure owner-create --help` fell through to the normal two-file argument check and returned `USAGE`. The CLI now returns a local JSON help object describing the exact config and input fields. It opens no files and starts no service; ordinary argument validation is unchanged.

The focused test `tests/owner-create-help.py` passed against the task-built debug CLI: both `--help` and `-h` returned exit 0 with the documented shape, while missing required arguments still returned nonzero `USAGE`. The temporary HOME remained empty. The test's stdout was tool output only; no standalone log was saved.

Validation command: `PATH=/tmp/peerwork-rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin:$PATH CARGO_HOME=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-target/cargo-home CARGO_TARGET_DIR=.test-data/owner-create-help-t071/target cargo build --locked --offline -p peerwork-cli --bin peerwork` (session 65233, completed successfully; Cargo reported 5m01s). Then `python3 tests/owner-create-help.py .test-data/owner-create-help-t071/target/debug/peerwork && .test-data/owner-create-help-t071/target/debug/peerwork secure owner-create --help` (exit 0). `git diff --check` passed.

Source SHA-256: `87e7df98f96ce30f1b7aa94a22ab1b5a1bb0ded434eb3cdc0f0bf237039aec7e`; regression SHA-256: `3669fe2b94b27f0800cdfa782e3cad8dd1f42b2c688f39d15e8315b8ceb9a6b0`; debug CLI SHA-256: `56a53af90da82d03a019cc39de9fd090da2c1e96b1985b4d16d54f6cb35e16fa`. This is a source-built debug CLI result only; installed-cohort behavior was not tested.
