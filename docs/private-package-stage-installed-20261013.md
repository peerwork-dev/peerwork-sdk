# Installed PRIVATE package staging

The installed three-interface staging smoke passed in session `50574` (exit 0) on 2026-10-13. The immutable SDK source is `a0908eecc37fec204644b1eec2913ed216f6b1cb`, which includes committed runtime stage API `84b907630dfb5d1a06ed394f56216a0d334db2c5` and the Python/Node/CLI facade. `git archive` SHA-256 is `9c5ae277b5b79e6df2a239102e5010bd2d9df405272caa8aba9d4931c66181e6`; its `secure_private_install.rs` SHA-256 is `c9fa20386c8b8e81faf783f5312ff20b6547ff7542dec5d3b08519ba14531d63`. The separately committed test is `d3504d2c15662730dfa5c767435fd824e57691c2`, file SHA-256 `5ac8bf1459ee5518a00aeb7af2d1e87969bf62d5bd01aa55e05f46f7f8071278`. It supplied that expected runtime hash externally and refused a mismatched extracted source. The service bridge came from the archive, with tracked reference root `/root/workdir/message/.worktrees/e2ee-main-integration-20261006` at `f828b6c50a0a58d1e718af90f653b214adcc3328`. Current uncommitted PRIVATE BEGIN/PAGE/END runtime work was outside the archive.

Rust 1.89 offline locked CLI+Node release build `46102`, Python wheel build `84440`, facade pack `43925`, platform pack `69888`, and fresh offline wheel/npm installs all exited 0. Artifacts have these SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| CLI `peerwork` | `41b3f2626d1dce47b42ed24573a9053b5fffe360f393567c40524c59d81de26b` |
| Node native module | `5f49183f48491129e002dc77ad1f8140182d9fafffa01f6d2c94e5e1277e3e4b` |
| Python `manylinux_2_38_x86_64` wheel | `8035a5d7a3f36460607a45bf660feb723183e2fa9b73424d9557ac0962380591` |
| Node facade tarball | `24b09218a3f83a2ef2729f2515f181d3236346200486e435f41123bf3ad207d9` |
| Node platform tarball | `1efb2acf8ab6419bacbdd2a0d330bc9204cacd44c5a1b8bb3ce174449c6166d9` |
| Installed wheel `RECORD` file | `c82b6c7cb749e43a35a4d523a19e5cb4f1b35ddefbf69b70fa9c217fd10ef4a5` |

The exact successful command from the SDK worktree root was:

```sh
PEERWORK_TEST_SDK_ROOT=$PWD/.build-artifacts/private-stage-a090/source \
PEERWORK_TEST_STATE=$PWD/.build-artifacts/private-stage-a090/build/stage-state-1 \
PEERWORK_TEST_NODE=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
PEERWORK_TEST_NODE_PACKAGE=$PWD/.build-artifacts/private-stage-a090/install/node/node_modules/@peerwork/agent-sdk \
PEERWORK_TEST_CLI=$PWD/.build-artifacts/private-stage-a090/build/target/release/peerwork \
PEERWORK_TEST_STAGE_SOURCE_SHA256=c9fa20386c8b8e81faf783f5312ff20b6547ff7542dec5d3b08519ba14531d63 \
PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
.build-artifacts/private-stage-a090/install/venv/bin/python tests/installed-private-package-stage-smoke.py
```

The script created a native PRIVATE structured workspace, selected the exact `conformance/public-package-vectors.json` closure with root digest `a7b9713067524ab85e988be2e665998e15a42c813c60e0a92880afec32b5c95c` and protocol digest `a37c72d1f4ac5999e5da49559de5c7d171663d526f04d59c9bada53c58dd0b05`, and submitted an encrypted stage part. The service applied the first POST but dropped its response. A test-only Python child deliberately withheld the generated stage and command IDs from its supervising process; that is an injected result-delivery loss, not a cancellation test. A fresh installed Node client discovered stage ID `EPDTk4FJm_RIBD5YeotiOKzWEXB8OqN7t1LuoI-0CGY` from protected local stage history. Installed CLI continued the exact saved stage to `STAGED` and repeated continuation without another commit. The source ID was `22226d30bb5a6c1d57d292289495de407ba242addaa4cfb3f40d09442cac7549`; this selected material needed one stage part, and the final signed sequence was 2. After the service stopped, installed Python, Node, and CLI local `stages` calls returned the same completed row without network access. The `RECORD` value above hashes the file only; not every installed member was independently rehashed.

`STAGED` means verified parts are saved. This test does not claim PRIVATE BEGIN/PAGE/END, installed or ACTIVE package status, multi-part stage coverage, natural Agent workflow compliance, or other platform execution.
