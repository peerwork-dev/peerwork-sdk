# Installed historical Owner attachment (2026-10-13)

The scripted Linux x64 installed-service test `74726` exited 0 against the pinned f828 reference service. It used a fresh offline-installed Python wheel, Node facade plus GNU x64 addon tarballs, and native CLI built from immutable SDK `git archive 0506b855280f52e62adae0c0656e597845206903` (tar SHA-256 `48fc9d0af5de718acae5151ac09e1b843b203e84e36d01196e9b46cfc92dd8bb`). This archive includes runtime attachment source `c4dc459`, three-interface facade `77440e8`, and public provenance correction `0506b85`; later core work and report-only commits did not enter the artifacts. The extracted attachment runtime SHA-256 was `73dcffb6d5670d0277c77c45cd3e70260253c5c098ed53619d0ecd51c1356e22`, Owner consumer source `1008c4ca3e08e852e47f9c269543ab61a8428fc2ac06b4045c79cec19b566316`, reference fixture `ed2f8b2e897e48da9229d4bea89879246e0c976cbbd0bf038bb93b6d9fc66d3e`, legacy source helper `1e3951c0ba5af8073f9cfd2beb47ae28db01f011e8a0d02da9a7761730a10d98`, and installed test `ada51e86a0b0a93ee880dc0e3463ab5ecb0f8207a3fa279e2d102dd2753f4f56`. The legacy TypeScript Owner source was a separate pinned pre-v3 worktree at `ae5d1151c2a1e72bc599eb4022291cf8496beba3`; its helper confirmed an actual signed PRIVATE wire-v1 source policy. The service fixture itself verifies the tracked f828 checkout and source hashes at startup.

Rust 1.89 locked-offline core/runtime/Python-native/Node-native/CLI `cargo check` passed on final `0506b85`; CLI+Node release build `61248` and Maturin wheel build `58550` exited 0. Fresh offline Python venv install/import `44256`, offline Node facade/platform tarball install/import, and package creation exited 0. All eight hashed wheel RECORD entries matched their SHA-256 and sizes. An earlier check using the ambient Cargo cache failed offline resolution of `tokio-macros`; the task-owned Rust 1.89 Cargo cache made the affected check pass. The first strict TypeScript consumer check after the metadata rename rejected its own stale comparison with `ATTACHED`; updating that task-local consumer to `HISTORICAL_TS_OWNER` passed without product changes. A first npm install command could not start because its requested working directory had not yet been created; the directory was created and the same offline tarballs installed successfully.

Artifact paths, relative to `.build-artifacts/historical-attach-0506b85/`, and SHA-256 values are:

| Artifact | Path | SHA-256 |
| --- | --- | --- |
| Archive | `build/sdk-0506b85.tar` | `48fc9d0af5de718acae5151ac09e1b843b203e84e36d01196e9b46cfc92dd8bb` |
| CLI | `build/target/release/peerwork` | `90799093a156cb2192300d6a6e86976f290eedb9527042e7b494a9125f0ab99b` |
| Wheel | `build/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl` | `fdf2ad5c886c2acab061393b931109f8f7fee8e58daa10febed963a97ddfea8f` |
| Node facade tarball | `build/peerwork-agent-sdk-0.0.1.tgz` | `51b0332b56c7bd744e38db492756d0592e347b900e1d0d538e2af1afe7ff882c` |
| Node GNU x64 tarball | `build/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz` | `35df9ab62d6ded02b9ac4c15ef998a8025d2fb13864dd31c573d01e1fe662f36` |
| Installed addon | `install/node/node_modules/@peerwork/agent-sdk-linux-x64-gnu/index.node` | `6b510fca4a86263965f9e310738ee883b3873f864a953179292301c8109d59aa` |

The helper created separate test-owned protected PKCS#8 PEM, TypeScript agent state, and WorkspaceClient SQLite intent store for four genuine legacy PRIVATE wire-v1 Owners. The caller explicitly paired those state and intent paths; matching local hashes prove that the declared inputs stayed stable, **not** that two independently created empty stores historically belonged together. In all three installed interfaces, pending signed action, nonempty unknown top-level intent map, and malformed admission map each returned redacted `SOURCE_UNRESOLVED`. A wrong expected Owner actor ID against the protected PEM returned redacted `IDENTITY_CHANGED` across Python, Node, and CLI; this does not test a forged PEM key or a current-policy Owner mismatch. Those refusals left fresh public attachment history empty and added no service commit. The valid source's current signed policy Owner was checked by native replay in the positive path.

The test then armed the fixture-only delayed authenticated journal GET (`PEERWORK_TEST_HISTORICAL_ATTACH=1`). The Python `attach_async` caller was cancelled only after the fixture reported that the GET had started; its generated attachment ID was not returned to that caller. A fresh public history query through Python, Node, and CLI exposed exactly one `PREPARED` row with `provenance=HISTORICAL_TS_OWNER`, null sequence/head, and the same saved ID `Ml0pgLfzR9sbidCZvHupQyafe9uKDcXflj50AdVaOHg`. Node `resumeAttachment` verified the source and signed current state and returned `ATTACHED` with that ID; Python and CLI exact resume returned the same result. Attachment and retries added no service commit. The test moved only its exportable legacy source directory aside, reopened the native Owner from its protected root, and verified signed read at sequence 1. Native encrypted `wiki.create` then returned one signed receipt for record `se0X8HGF-KfLWoxMNSB5ltGGgd4TTh_sqzgy6SJYAC0` by the attached Owner, whose exact title/body appeared in verified read at sequence 2. The service commit count increased exactly once for that action; exact retry added none. After service shutdown, all three interfaces returned the equal local `ATTACHED` history. This proves scripted public API/state behavior, not natural Agent instruction-following.

The first sandboxed installed invocation exited 1 before service startup because the tracked fixture's read-only `spawnSync git rev-parse` provenance check returned `EPERM`; it performed no SDK business operation. The unchanged artifacts/test ran once with approved local execution and fresh `attach-state-2`, session `74726` exit 0. The test command from the extracted source was:

```sh
artifact_root=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/historical-attach-0506b85
PEERWORK_TEST_SDK_ROOT="$artifact_root/build/source" \
PEERWORK_TEST_STATE="$artifact_root/build/attach-state-2" \
PEERWORK_TEST_LEGACY_ROOT=/root/workdir/message/.worktrees/peerwork-legacy-owner-client-20261013 \
PEERWORK_TEST_NODE=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
PEERWORK_TEST_NODE_PACKAGE="$artifact_root/install/node/node_modules/@peerwork/agent-sdk" \
PEERWORK_TEST_CLI="$artifact_root/build/target/release/peerwork" \
PEERWORK_TEST_ATTACH_SOURCE_SHA256=73dcffb6d5670d0277c77c45cd3e70260253c5c098ed53619d0ecd51c1356e22 \
PEERWORK_TEST_OWNER_SOURCE_SHA256=1008c4ca3e08e852e47f9c269543ab61a8428fc2ac06b4045c79cec19b566316 \
PEERWORK_TEST_LEGACY_HELPER_SHA256=1e3951c0ba5af8073f9cfd2beb47ae28db01f011e8a0d02da9a7761730a10d98 \
PEERWORK_TEST_REFERENCE_FIXTURE_SHA256=ed2f8b2e897e48da9229d4bea89879246e0c976cbbd0bf038bb93b6d9fc66d3e \
PEERWORK_TEST_LEGACY_COMMIT=ae5d1151c2a1e72bc599eb4022291cf8496beba3 \
PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
TMPDIR="$artifact_root/build/tmp" \
"$artifact_root/install/venv/bin/python" tests/installed-historical-owner-attach-smoke.py
```

The delay endpoint is a test fixture, not a public SDK operation. This selected source was quiescent and did not establish migration of its pending operation, completed-cache interoperability, or cryptographic pairing of the declared legacy stores. The test does not prove actual macOS/Windows execution, a dependency-closed lower-glibc release, or independent complete business flows per interface. Workflow compliance of a natural Agent remains unverified separately from this scripted business result.
