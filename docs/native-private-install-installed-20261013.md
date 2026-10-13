# Installed PRIVATE package continuation (2026-10-13)

The scripted installed-service test `tests/installed-private-package-install-smoke.py` at `8d7dbee391aae110dbd0b6bc452c355963d0a3eb` (SHA-256 `8ccc664eb5254eb7dedf42e6c35aaf236b8deb342a91350d4e508f5073913362`) passed in session `96498` (exit 0). It ran against the tracked local service at `f828b6c50a0a58d1e718af90f653b214adcc3328`, using a fresh installed wheel, two npm tarballs and native CLI. This is a Linux x64 scripted API and business test, not a natural Agent workflow or macOS/Windows release result.

The build input was `git archive b81f9ed95a0049409cb8eceeb916133b4d06cbb4`, SHA-256 `410fcc20c489ce8a04ec7dd91950e3d5beb02ebd87d201e07b1365f5a8c6ba37`. Its only difference from reviewed replay source pin `7bc6216` is `docs/snapshot-install-replay-20261013.md`; `git diff 7bc6216 b81f9ed -- crates bindings tests conformance third_party Cargo.lock Cargo.toml pyproject.toml` exited 0. The extracted source hashes were `crates/core/src/secure_replay.rs` `e4b440272d0daf1c08d9e83fa98477cf3a804fda67cd6b286990d472e62c5800` and `crates/runtime/src/secure_private_install.rs` `c261e0f90e98d39910040f72988502b02d6abbd65f5f6d657816d6d231c6c5d0`. The test required those independently supplied hashes before starting the service. The one-part source vector `conformance/public-package-vectors.json` had SHA-256 `a8d18264824cc00109ced8b4d244ebb51e566fd32ae62d164ca92e378ec924c8`.

Locked-offline Rust 1.89 release CLI/Node build session `32823` exited 0 in 2m29s; locked-offline Maturin wheel build session `35583` exited 0. The wheel installed with `pip --no-index --no-deps` into a fresh virtual environment, and both npm tarballs installed with `npm install --offline --ignore-scripts` into a fresh consumer. Clean installed Python and Node imports passed. Wheel RECORD hashes and sizes verified for all eight hashed entries. Artifact SHA-256 values: CLI `b23c13a193cd92f645aba303b0f5cdca5a5c9bc92ebe080bf22ed7e5b7214363`; wheel `05bfbd217bfc495d717d6d4fd934499079b565eee44a0cda89adf61b76fed8ee`; Node facade tarball `57fc8618e34ec0eca59aea8ec5b1abfff97bb279d9750542f5ebc59967b7e754`; GNU x64 platform tarball `ea9cf84fea705ad43e8f983f16f3a3a0af4dd86ceb71eb1ffa15992e19940fe7`; installed addon `76832386ef2cc8c48b6242f8d7d024dd7864c32d0022217e86a082129e472d9c`.

The test created a native Owner PRIVATE structured workspace and read signed sequence 1, then staged the exact one-part closure. Staging returned the expected root and protocol digests, source ID, part count 1, and verified STAGED progress. For BEGIN, the fixture applied the signed POST and dropped its reply. A child Node process intentionally withheld the generated BEGIN command ID from its supervising caller. A fresh Python Owner client recovered that ID, stage ID, instance ID and protocol digest from protected local `installs()`; this is withheld-result recovery, not an async cancellation test. CLI END also received an applied-but-dropped response; Node exact continuation returned ACCEPTED without another commit. A signed Owner read reported ACTIVE and the exact installed instance/protocol digest. Node authored an encrypted `proposal.propose`; Python and CLI retried the saved action ID, and signed receipt/readback agreed on the Owner actor, one record ID, and exact title/body. CLI repeated installer continuation without another commit. The final verified read reported sequence 5 and the fixture's service head/count agreed. After stopping the service, Python, Node and CLI local installs listings matched on the saved BEGIN ID. The test printed workspace `mcKOTnIJT-cGxMtNqd25rfC2Grtmy88gTeyRR5BQ-nM`, stage `UZd97QHlzbNS-M9m95pkqlTmANyTJNdR7H_eXPJLLCA`, BEGIN ID `pokSSVc5MS9bOfWuSwMaqoiVYbuYIvBXARf6Bc6_9XU`, instance `IVID_AyX3MP8Svj5cHEVm4u0klNhw3mdrNPrTnevtxk`, and record `j2bEFUlmAnLTL9IjqfngeiB5WIMFlNOrRe09lS_cVUI`.

The first invocation stopped before service startup because the process sandbox denied the fixture's `spawnSync git -C ... rev-parse HEAD` with `EPERM`; it performed no SDK business operation. The unchanged artifacts/test ran with a fresh `private-install-state-2` under approved local service execution and passed. The affected invocation, from the SDK worktree, was:

```sh
artifact_root="$PWD/.build-artifacts/private-install-b81f9ed"
PEERWORK_TEST_SDK_ROOT="$artifact_root/source" \
PEERWORK_TEST_STATE="$artifact_root/build/private-install-state-2" \
PEERWORK_TEST_NODE=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
PEERWORK_TEST_NODE_PACKAGE="$artifact_root/install/node/node_modules/@peerwork/agent-sdk" \
PEERWORK_TEST_CLI="$artifact_root/build/target/release/peerwork" \
PEERWORK_TEST_INSTALL_SOURCE_SHA256=c261e0f90e98d39910040f72988502b02d6abbd65f5f6d657816d6d231c6c5d0 \
PEERWORK_TEST_REPLAY_SOURCE_SHA256=e4b440272d0daf1c08d9e83fa98477cf3a804fda67cd6b286990d472e62c5800 \
PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
TMPDIR="$artifact_root/build/tmp" \
"$artifact_root/install/venv/bin/python" "$artifact_root/source/tests/installed-private-package-install-smoke.py"
```

This covers the official one-part/empty-history PRIVATE install path and one encrypted record effect. PRIVATE PAGE/nonempty history, package-family parity, other operating systems, and Agent instruction-following remain separate acceptance work.

The same installed artifact set also passed the existing **PUBLIC composed Owner/adopter consumer regression** in session `30695` (exit 0). Its committed test `tests/installed-native-owner-adopter-workflow.py` had SHA-256 `41a16bb63d72c0e03d6fce04050d02e14fd71ad52e5bb1b9346ce2c29deae58c`, the composed vector SHA-256 was `ea072b766172a211f1f413ea61c5166e10a660bd46a1adc422cd2dddac2c12dc`, and its externally supplied Owner runtime source hash was `a5968ec17d07355a256c47fc6ab5996ec3f7a216965c76da1493e25de0c3b9ac`. Using fresh `owner-adopter-state-1`, the affected invocation from the SDK worktree was:

```sh
artifact_root="$PWD/.build-artifacts/private-install-b81f9ed"
PEERWORK_TEST_SDK_ROOT="$artifact_root/source" \
PEERWORK_TEST_STATE="$artifact_root/build/owner-adopter-state-1" \
PEERWORK_TEST_NODE=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
PEERWORK_TEST_NODE_PACKAGE="$artifact_root/install/node/node_modules/@peerwork/agent-sdk" \
PEERWORK_TEST_CLI="$artifact_root/build/target/release/peerwork" \
PEERWORK_TEST_OWNER_SOURCE_SHA256=a5968ec17d07355a256c47fc6ab5996ec3f7a216965c76da1493e25de0c3b9ac \
PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
TMPDIR="$artifact_root/build/tmp" \
"$artifact_root/install/venv/bin/python" "$artifact_root/source/tests/installed-native-owner-adopter-workflow.py"
```

The public test observed PAGE, PAGE, END, END progress for the exact composed closure, then native distinct-actor offer/consent/delivery/receipt, proposal, adoption and task effects with final verified sequence 10 and duplicate-free retries. It printed Owner `AQ7M9XJt5cCv_WbBGPwoiK_rjlMbESZG5wsQxq3fX3g`, recipient `eaULsErdLFnIlWRF8GDlnQIe0PQzMtOmh61Hnbk8ncY`, candidate `qY6L9M9yu77G3GGM-J__xPMjFr_WzYKrUEu0cyctm0c`, and task `SYyr6QN34KFoBZtGnmV4pKGp2CXRdVNGyiykj4eLvGY`. This rerun demonstrates that the corrected strict replay validator still accepts a legitimate PUBLIC composed nonempty snapshot on installed artifacts. It does not exercise PRIVATE nonempty PAGE or supply an independent installed tamper-negative test.

## PRIVATE composed two-part and nonempty PAGE follow-up

The optional composed mode was committed separately at `05d2966` (`tests/installed-private-package-install-smoke.py`, SHA-256 `fa7cd7f70344135930a91224a556fa478354d9fc42856bd1b0c1b70ca7a3d705`), after the original one-part result above. It used the **same installed b81 wheel/npm/CLI artifacts** and a fresh `private-composed-state-1`; session `36454` exited 0. The test required the same external installer/replay source hashes plus official composed vector SHA-256 `ea072b766172a211f1f413ea61c5166e10a660bd46a1adc422cd2dddac2c12dc`, root package digest `2891b2dd0ab0f5229917a3b9917ef08bed4ac60539ff6c296b445ba7e89bf669`, protocol digest `4bbc29376d4c509319f5f825a4d36a627d83a54153d5cefb8762b6d23bcaa9c0`, and vector source digest `c6ae98e80955fe38dbdac4ae5ccc823cd80c2027f4b3c9f34246527494cfc6a6` before starting the service.

Native Owner created the PRIVATE structured workspace and an encrypted wiki record before staging. Signed read at sequence 2 verified its record ID `0NQopA_I29D7kkeI4A4vRGZTiYfWYNI0lBtBWCmTsKg` and exact title/body. The committed official composed closure staged as two applied source parts, with root/protocol digests matching the vector. Node BEGIN received an applied-but-dropped response and withheld its generated ID from the supervising caller; fresh Python `installs()` recovered BEGIN `efj4pZ2aVduLklJo0p_zs98WWRG4an-EXIf9detZrck`. The first CLI continuation authored `secure.structure.page` and its POST applied with a dropped reply. Subsequent Node continuation observed a second PAGE and END; the three distinct step IDs were `4TDTvUBYHFEzQ12pGYtkON00Wep3mh5S_JOC6wl_lvc`, `Ro7-aplJFYWo7y-mwcDJ2FGz1CR5QJj_TO0u4EHpnYM`, and `K8YELR3xWu9Bpyb0nerEB3a-f2zskhdg7hTl4rMGJQU`. Exact saved continuation reached ACCEPTED without duplicate commits. Signed ACTIVE read preserved the old record's ID/title/body and installed the expected protocol/instance. Node authored encrypted `proposal.proposal.propose`; signed receipt/readback verified one candidate record `VRuOick_h-6nC73G9GWpv_9c3HJdKLbFGAcxcuPciVs`, exact title/body/Owner author, and the old record again. CLI repeated saved action/install retries without another commit. Final verified sequence was 9; after service shutdown, Python/Node/CLI local installs rows matched on the BEGIN ID.

The observed staged `source_id` was `664a127a00192b89d96a3b29829b6c5a0e16b80512105a562472c6cab44e2d48`. It is not the vector's `source_digest` and is not expected to equal the earlier two-part stage-only run's source ID `8605a84aa3c735644f520fef426eab02d1c1f250ef359ace6392913a687de75b`: `package_source_id` hashes the exact workspace source checkpoint together with the canonical material hash. The material/vector digests above identify the selected package; the source ID binds this particular staging origin and prefix. The full affected invocation from the SDK worktree was:

```sh
artifact_root="$PWD/.build-artifacts/private-install-b81f9ed"
PEERWORK_TEST_SDK_ROOT="$artifact_root/source" \
PEERWORK_TEST_STATE="$artifact_root/build/private-composed-state-1" \
PEERWORK_TEST_NODE=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
PEERWORK_TEST_NODE_PACKAGE="$artifact_root/install/node/node_modules/@peerwork/agent-sdk" \
PEERWORK_TEST_CLI="$artifact_root/build/target/release/peerwork" \
PEERWORK_TEST_INSTALL_SOURCE_SHA256=c261e0f90e98d39910040f72988502b02d6abbd65f5f6d657816d6d231c6c5d0 \
PEERWORK_TEST_REPLAY_SOURCE_SHA256=e4b440272d0daf1c08d9e83fa98477cf3a804fda67cd6b286990d472e62c5800 \
PEERWORK_TEST_PRIVATE_COMPOSED=1 \
PEERWORK_TEST_VECTOR_SHA256=ea072b766172a211f1f413ea61c5166e10a660bd46a1adc422cd2dddac2c12dc \
PEERWORK_TEST_ROOT_DIGEST=2891b2dd0ab0f5229917a3b9917ef08bed4ac60539ff6c296b445ba7e89bf669 \
PEERWORK_TEST_PROTOCOL_DIGEST=4bbc29376d4c509319f5f825a4d36a627d83a54153d5cefb8762b6d23bcaa9c0 \
PEERWORK_TEST_SOURCE_DIGEST=c6ae98e80955fe38dbdac4ae5ccc823cd80c2027f4b3c9f34246527494cfc6a6 \
PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
TMPDIR="$artifact_root/build/tmp" \
"$artifact_root/install/venv/bin/python" "$PWD/tests/installed-private-package-install-smoke.py"
```

This follow-up proves one existing encrypted record, two committed source parts and two observed PRIVATE PAGE steps before END on installed Linux x64 packages. It is distinct from the core's separate 51-record/four-PAGE boundary work and does not establish all package families, cancellation semantics, other operating systems, or natural Agent workflow compliance.
