# Installed native Owner and adopter composed workflow, 2026-10-13

The accepted run used `git archive dcc1337` (SHA-256 `7126ca5163abbbc3a0694d914bfd64a6c240173eea1c404116c679e77bab9ee7`) extracted into `.build-artifacts/owner-adopter-dcc/source`, with no uncommitted source overlay. `dcc1337` includes the committed PRIVATE Owner runtime source `7c0c2b8`, but this test exercises the PUBLIC Owner/adopter flow only; no PRIVATE Owner wrapper is present in the installed packages. The separate installed test is `33f808d` (`tests/installed-native-owner-adopter-workflow.py`, SHA-256 `41a16bb63d72c0e03d6fce04050d02e14fd71ad52e5bb1b9346ce2c29deae58c`). Its required external Owner runtime source hash was `5c40aa4a85aa38eb06955e956176ab123a39e44b9bc107e8abc334aa8d4b5b5a`, checked against the extracted `crates/runtime/src/secure_owner_create.rs` before service startup. The local tracked HTTP service checkout stayed at `f828b6c50a0a58d1e718af90f653b214adcc3328`.

Rust 1.89 offline locked CLI/Node release build session `22650` exited 0 in 2m11s; Maturin wheel build session `95443` exited 0 in 28.18s. The wheel was installed offline into a fresh Python venv; the Node facade and linux-x64-gnu platform tarballs were packed with task-local npm cache and installed offline into a separate task-local package directory. The wheel RECORD validated all 9 entries' SHA-256/size fields. Artifact SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| CLI `peerwork` | `e01b43ee4661b71ed29ace6a64906e7854ec04c1e64366832931e5eab77ef0b7` |
| Node native `.so` | `8dc1b651a88a1200a54c3cfa197366fef46b8023e593410d1d9b9c0c75fb815e` |
| Python `peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl` | `75f177c2d3195b72918827fc6e471a5d5429549e5050d118337903cf8f182063` |
| Node facade `.tgz` | `4988da46baa856b8b13af62b60bfc30828f2370e1e3624bb3fef937497cff0bd` |
| Node linux-x64-gnu platform `.tgz` | `d6d0bd08381996aa86076edde901490b980f288217262bb41c9d05a3f5dce6a9` |

The affected installed command was:

```sh
PEERWORK_TEST_SDK_ROOT=$PWD/.build-artifacts/owner-adopter-dcc/source \
PEERWORK_TEST_STATE=$PWD/.build-artifacts/owner-adopter-dcc/build/owner-adopter-state-2 \
PEERWORK_TEST_NODE=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
PEERWORK_TEST_NODE_PACKAGE=$PWD/.build-artifacts/owner-adopter-dcc/install/node/node_modules/@peerwork/agent-sdk \
PEERWORK_TEST_CLI=$PWD/.build-artifacts/owner-adopter-dcc/build/target/release/peerwork \
PEERWORK_TEST_OWNER_SOURCE_SHA256=5c40aa4a85aa38eb06955e956176ab123a39e44b9bc107e8abc334aa8d4b5b5a \
PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
.build-artifacts/owner-adopter-dcc/install/venv/bin/python tests/installed-native-owner-adopter-workflow.py
```

Session `79623` exited 0. The installed native Owner created a PUBLIC structured workspace; an applied but dropped genesis response left a protected pending operation, and a fresh client recovered its generated command/workspace IDs through `operations()` and exact `resume()` without a second genesis commit. The Owner authored a wiki record, installed the source-pinned official composed proposal/adoption/task closure through two PAGE and two END continuation results, and verified the wiki record ID/title/body survived. Exact returned package and protocol digests matched `conformance/official-proposal-task-composition.json`. The recipient was a distinct native-created actor, published its certificate through native APIs, and the Owner looked up the same signed certificate with explicit actor/key pins. Native Owner offer, native recipient ACCEPT, Owner delivery, and recipient receipt reached authorized membership with the proposal ADOPTER scope. No tracked TypeScript Owner or recipient setup supplied the business effects.

The Owner's native proposal yielded candidate record `7zgj3bLrj75l77N8pSAxGT6DsjG0xAPWWYBO4WXGquw`; signed readback preserved title/body/author. The native recipient's adoption receipt identified its distinct actor, and authenticated instance state became `adopted=true` with `adopted_ref` equal to that exact candidate record/revision; the saved action operation retained the exact input ref. The Owner's task yielded record `oF5z9gL6rM2QWnO9tHjKUqzK5DE5_Je9ncfmvyOgvoE`; readback verified its schema/title/author, `tasks.based_on_candidate` relation to the exact candidate revision, and entity head revision 1. Node continued install and reconciled proposal/task; CLI retried adopter and Owner commands. Signed service head stayed at final sequence 10 after those retries. This is a scripted business/runtime proof, not natural Agent workflow compliance, and the standalone anonymous catalog fixture was not used as package publication/provenance for this workspace.

Failure provenance is separate. Initial immutable `72aadb8` run `34526` stopped after composed install on an overstrict test assertion comparing the entire wiki payload to only title/body; test-only `f9d29ca` asserted those fields by the signed record ID. Its run `94229` reached native offer/ACCEPT/delivery but recipient receipt refused before durable grant staging: `verified_secure_grant::valid_scopes` incorrectly base64url-decoded the source-valid opaque `"z"*43` instance ID. Core corrected that predicate in `dcc1337` and focused tests passed 2/2; the test instance ID was not changed. The first dcc invocation then failed before service startup because `f9d29ca` hardcoded the prior Owner runtime source SHA. Test-only `33f808d` required the exact external dcc SHA shown above, and the same freshly installed dcc packages passed in `79623`. No natural-Agent/tool-call compliance or macOS/Windows execution is inferred from this local Linux smoke.
