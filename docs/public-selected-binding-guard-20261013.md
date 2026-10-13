# PUBLIC selected-binding guarded vote, 2026-10-13

The opt-in Rust actual-service gate at `4dc553b08e5eb384d934737b362013d676a2b748`
passed 1/1 in 54.58 seconds against the tracked reference service at
`f828b6c50a0a58d1e718af90f653b214adcc3328`. The committed test file
`crates/runtime/src/secure_public_install.rs` has SHA-256
`2f25c425e06f66efd30fc8c9ceda1890131cd45a97d26987768419fe4e90c988`;
the source-derived vector `conformance/private-package-options-reference.json`
has SHA-256 `240ecca06c1a5783b0d2cda9e089b1617fce735a63473b11bcbbcea8d7a7380f`.
The service bridge SHA-256 is
`50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0`.
The passing log is
`.build-artifacts/public-selected-binding/actual-service-latest-revision.log`,
SHA-256 `5ef2027bed0d3471cb0ea8a76e364d791acde08631e2c8220b4703242d727c4a`.

The test created one native PUBLIC structured Owner workspace. It installed
the same reference closure twice with independently pinned protocol digests:
default `e4f3e647543a1294ff459b44964e4c62c4f16a99d77138c8e048c092eceaa86a`
and selected AUTHOR
`ab2a4c9c6cd39884796c7e8f4196c9925b2e2e06db3a13ca6ac07f9eaf362f35`.
Both instances granted the Owner only AUTHOR for `vote`. The default
REVIEWER-guarded `vote` returned the exact native `PublicActionError::Prepare`
before packet signing/POST and did not add a service commit. The selected
AUTHOR `vote` reached signed ACCEPTED and added one commit; the Owner's
verified read found its latest instance revision 2, selected digest and
`state.count=1`. Exact install and action retries returned the saved results
without extra commits. These are native business-path assertions; they do
not test an Agent's instruction-following or natural workflow. Workflow
compliance is **unverified**.

The successful command ran from
`/root/workdir/message/.worktrees/peerwork-sdk-native-20261012` with Rust 1.89,
the existing offline Cargo cache, an isolated target and pinned Node 24.20.0:

```sh
env PATH=/tmp/peerwork-rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin:$PATH \
  RUSTUP_HOME=/tmp/peerwork-rustup \
  CARGO_HOME=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-target/cargo-home \
  CARGO_TARGET_DIR=/root/workdir/message/.worktrees/peerwork-sdk-private-options-20261013/.build-target \
  TMPDIR=/root/workdir/message/.worktrees/peerwork-sdk-private-options-20261013/.build-target/tmp \
  RUSTC=/tmp/peerwork-rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin/rustc \
  RUSTDOC=/tmp/peerwork-rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin/rustdoc \
  PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
  PEERWORK_NODE_BIN=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
  PEERWORK_TEST_PUBLIC_SELECTED_BINDING=1 \
  cargo test -p peerwork-runtime --offline --locked \
  secure_public_install::selected_binding_service_test::actual_service_public_selected_binding_allows_guarded_vote \
  -- --exact --nocapture \
  > .build-artifacts/public-selected-binding/actual-service-latest-revision.log 2>&1
```

Three earlier one-test runs remain distinct. `b46cf90` failed before the
guard because the test read `begin_command_id` from a PUBLIC submit DTO that
actually exposes `command_id` (log SHA-256
`0bc663309c54c243dcde5173cdbe517e212202ca78045a273e0ef9d0296b9c0e`).
After test-only correction `f1fe10a`, the test expected server HTTP 409 for
the default guard, but native preparation rejects it locally before POST;
the actual error variant was not printed in that run (log SHA-256
`1673f0181de9941888b9344828333c71963bea836abf4076824204de00a05295`).
At `6af9400`, the exact native Prepare/no-commit negative and selected
ACCEPTED/+1 were reached, but the test inspected the first historical
instance revision, whose count was still zero (log SHA-256
`ee2c067e59988d109abe7b54ff2b05c8077b462acb5758ae473133bbdf0f6ed8`).
The final test-only revision selects the latest revision for the exact
instance ID and retains the count assertion. None of these three failures
established selected-binding business success.

This gate is a single Rust/native service test with a synthetic Owner and
the pinned reference vector. It does not establish installed Python/Node/CLI
use, independent interface completion, publisher authenticity, macOS or
Windows operation, or Agent workflow compliance.
