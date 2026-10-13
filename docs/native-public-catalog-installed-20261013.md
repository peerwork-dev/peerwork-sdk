# Installed anonymous catalog read, 2026-10-13

The wrapper source is `72aadb8`; the installed test is `2d72dcc` (`tests/installed-public-catalog-smoke.py`, SHA-256 `9c7291debc8b8fa3a82a6e411cc8cf666280e4ac8535bf8d04ad73efde1841ae`). `git archive 72aadb8` was extracted into `.build-artifacts/catalog-owner-72/source` without the contemporaneous PRIVATE admission worktree changes; archive SHA-256 `ca564f7c2db0f2ae4b2b98ee4022862e38a403ffbd01d8a5ecdeff4ac67e7643`. The reference service is the pinned `f828b6c50a0a58d1e718af90f653b214adcc3328` local checkout, and the fixture checks that its compiled catalog HTTP modules match pinned hashes before serving. This is a scripted installed-interface test, not natural Agent workflow compliance or external publisher authentication.

Rust 1.89 offline locked CLI/Node release build `59685` exited 0 in 2m06s; Maturin offline locked wheel build `20188` exited 0 in 1m10s. Node package creation used `node bindings/node/scripts/package-platform.mjs linux-x64-gnu ../build/target/release/libpeerwork_node_native.so ../build/platform` and `cd bindings/node && npm pack . --ignore-scripts --offline`, followed by packing the platform directory. Fresh task-local Python venv and Node package directory installed the wheel and both tarballs offline. The wheel RECORD had 9 entries with matching SHA-256 and sizes. Artifact SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| CLI `peerwork` | `ffee0022210a70f6b80eed2e65f07d0d30fb28f73722f12bbf3f2275a2f3038f` |
| Node native `.so` | `54f395c0081507049751b188995cae857382d6e986a62cd5b28e2f62cbb6b293` |
| Python wheel `peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl` | `fcd84a944fb9be833442a8c90d5740dceb69392cdb00826517046ddf82f2e655` |
| Node facade tarball | `4988da46baa856b8b13af62b60bfc30828f2370e1e3624bb3fef937497cff0bd` |
| Node linux-x64-gnu platform tarball | `88420b6fab065f98afc1ba79699e14a9d1ca32a12ef9b1f30235b4d6b5dfb1d4` |

The installed command was:

```sh
PEERWORK_TEST_SDK_ROOT=$PWD/.build-artifacts/catalog-owner-72/source \
PEERWORK_TEST_STATE=$PWD/.build-artifacts/catalog-owner-72/build/catalog-state-2 \
PEERWORK_TEST_NODE=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
PEERWORK_TEST_NODE_PACKAGE=$PWD/.build-artifacts/catalog-owner-72/install/node/node_modules/@peerwork/agent-sdk \
PEERWORK_TEST_CLI=$PWD/.build-artifacts/catalog-owner-72/build/target/release/peerwork \
PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
.build-artifacts/catalog-owner-72/install/venv/bin/python tests/installed-public-catalog-smoke.py
```

The sandboxed first attempt failed before HTTP startup because the fixture's read-only `git rev-parse` child was denied `EPERM`; the same pinned command under approved unsandboxed execution passed, exit 0. The first npm install attempt also failed `ENOTDIR` by discovering an unrelated parent `node_modules`; a task-local `package.json` plus `npm install --prefix` isolated the installation and passed. These are invocation/environment failures, not catalog verifier failures.

The actual local Hono HTTP fixture served two source-vector packages. Installed Python searched anonymously and inspected digest `a7b9713067524ab85e988be2e665998e15a42c813c60e0a92880afec32b5c95c`; installed Node inspected `0a72a567a373699c12f316abd8ffa86dda6eb54da344dc5edc96648647d557be`; CLI searched the same listing. The fixture rejected auth/cookie/read-proof headers. Two subsequent exact GETs returned a tampered body and a different canonical bundle; Python refused both with `CATALOG_DIGEST_MISMATCH`. Uppercase digest and a one-byte listing budget yielded `CATALOG_INPUT_INVALID` and `CATALOG_RESOURCE_LIMIT`. The test does not establish package publication, publisher provenance, or compatibility of this separate catalog with a secure workspace install.

The stronger test-only successor `8bc27c8` (test SHA-256 `f566efa9614b9512d36b5b3a82f23bade5fb84991aafa45c73d2d678daf0bad6`) ran against the **same installed artifacts** in fresh task-local state `catalog-state-3`, session `19031`, exit 0. Each interface used its own fresh pinned HTTP fixture so the third and fourth by-digest responses deterministically carried tampered and substituted bytes. Python, Node, and CLI each searched both digests, inspected both exact bundles, refused both bad responses as `CATALOG_DIGEST_MISMATCH`, refused uppercase digest as `CATALOG_INPUT_INVALID`, and refused a listing under the one-byte budget as `CATALOG_RESOURCE_LIMIT`. The earlier `2d72dcc`/`08f6a08` narrower result remains separately attributed.
