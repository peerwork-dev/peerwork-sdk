# T125 GNU coordination test selection (2026-10-16)

The prior GNU experimental job ran the default `cargo test --workspace --locked` release-build prerequisite. Core passed 104 tests. Runtime passed 186, failed two, and ignored two. Both failures were the `secure_owner_coordination::tests::actual_service_{private,public}_coordination_enable_upgrade_recovery` tests, each stopping at the explicit `PEERWORK_REFERENCE_ROOT` gate before service startup. The release job had no reference checkout, Node binary, or fresh retained coordination test directory configured. These tests are integration tests of an external reference service fixture, not self-contained default unit tests.

Both named tests now carry `#[ignore]` with their required inputs. Their `actual()` harness still requires all three explicit inputs, starts the real reference-kernel HTTP service, and retains every signed effect, recovery, and no-duplicate assertion. This follows existing opt-in actual-service test selection in the runtime crate (`kernel_client.rs` and `transport.rs`). It does not substitute for the installed release service gate.

Run each actual-service test explicitly from the SDK root with a **different nonexistent** protected directory for each case:

```sh
export PATH=/tmp/peerwork-rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin:$PATH
export CARGO_HOME=$PWD/.build-target/cargo-home
export CARGO_TARGET_DIR=$PWD/.build-target
export PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006
export PEERWORK_NODE_BIN=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node
PEERWORK_COORDINATION_TEST_DIR=/tmp/peerwork-coordination-private-fresh cargo test --offline --locked -p peerwork-runtime --lib secure_owner_coordination::tests::actual_service_private_coordination_enable_upgrade_recovery -- --ignored --exact --nocapture
PEERWORK_COORDINATION_TEST_DIR=/tmp/peerwork-coordination-public-fresh cargo test --offline --locked -p peerwork-runtime --lib secure_owner_coordination::tests::actual_service_public_coordination_enable_upgrade_recovery -- --ignored --exact --nocapture
```

The directory paths above are examples and must be absent before each invocation; reuse a retained directory only for inspecting its earlier evidence. These are local reference-service trials, not production service tests.

Verification pending the combined hosted GNU job: the default workspace suite should run without these external inputs and report the two additional ignored tests (runtime expected 186 passed, zero failed, four ignored, subject to other source changes). The local focused Cargo command selected the intended `.build-target` but began recompiling `peerwork-core`; it was stopped after approximately six seconds (exit 130) before any test ran, because the matching core cache was not warm. Static source/diff checks are reported with the commit handoff. The original two job failures remain recorded; the new selection has not yet passed CI.
