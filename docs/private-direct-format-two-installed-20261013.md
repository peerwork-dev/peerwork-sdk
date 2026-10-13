# Installed PRIVATE DIRECT format-two checkpoint (2026-10-13)

The scripted Linux x64 installed test exited 0 in session `41310` on a single SDK archive from commit `78429a9a6022f22ef250a55a3ac5dec00e5c93ef`. The archive is `.build-artifacts/private-direct-format2-78429a9/build/sdk-78429a9.tar`, SHA-256 `6a8c7eed0195ce391286425c6f8a4e2bff3597334b43121c53cee7c710f8d822`; its extracted source is the adjacent `build/source`. The test was the archived `tests/installed-private-direct-format-two-smoke.py`, SHA-256 `fd40cfe42703da02ae83e53216f43d4baa8292e711ecf0eed62d6bfda49ae0db`. The separate PUBLIC test archived alongside it is SHA-256 `61ce5fa0e9155b12eaf582a776af1085590c1dc29be1b971e892721c39ebb4de`; this report makes no PUBLIC installed claim.

Full artifact paths and hashes are retained in `build/manifest.sha256` under the artifact directory. The CLI `build/target/release/peerwork` is SHA-256 `9d8810217abc367adf3f897c199ea0ae8bf90afb7171fbd33a7aa017a8e6eb29`; Python wheel `build/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl` is `0f4108796687d6a8687420f8ca52ceb643856f9fad1461157b9ac69c103a3870`; Node facade tarball `build/peerwork-agent-sdk-0.0.1.tgz` is `db78746d9183f913c7a8eae9f1abf7886d0d9c2e394f49df6c0d0ab881b70c6b`; GNU x64 addon tarball `build/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz` is `77926ad75ad50b152068903ee48458324ab35144e2afd808b92c739e8eef6c24`. Both the built and fresh installed addon are SHA-256 `0fb354ea7273126bd4ea706f2d5d1ef2d705262930352e3023cef7b518a3d368`. Root separately ran `sha256sum -c` over all seven manifest entries. The wheel's `manylinux_2_38` tag is local artifact scope, not the intended lower-glibc release gate.

The extracted source retained exact guarded file hashes: `public_direct_install.rs` `c356220b74e4407998d4ad2e84a7c0a159478a425f030c6989ee0e18dbdb02ef`, `prepared_private_install.rs` `93237fde9e9ea7483b0631169d3983139fa17f75fdc0b53515ff318deffd7207`, `secure_private_install.rs` `098c066d6bf1ffce624c13ac9673fe1cda012478238d8c52b85b493cecfbff36`, `secure_owner_format_transition.rs` `09b440b27962e91c144a8de5ac997482175af4168d6fc297cbac127615cd044f`, `tests/reference-kernel-server.mjs` `50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0`, and `conformance/private-direct-format-two.json` `9e96c0eec94150d6b890c9988bec22272d338fa9a930d20e34a1ebfa34b2ddac`. The vector was generated from pinned `tests/format-two-material.mjs` SHA-256 `70e3085e105344c80edc15216e736a8b69028185681d3fffd0dd4e850ccd63cf` against reference service source `f828b6c50a0a58d1e718af90f653b214adcc3328`. The independently derived DIRECT composition source digest `b792d58a1c33218f121d7c742ca85bf63c411ab3aa5733ff88cc8b919f05496a` is distinct from the pre-resolution compiled source digest; the source-level derivation and the earlier corrected oracle are recorded in `docs/private-direct-format-two-20261013.md`.

The offline Rust 1.89 CLI/Node release build `50017`, Maturin wheel build `95098`, platform/facade tarball pack `30507`, fresh Python install/import `37155`, and fresh Node two-tarball install/import each exited 0. Eleven installed wheel RECORD entries with SHA-256 and size were checked against installed files. The archive was built once. The prior combined four-crate locked-offline check `96417` passed on the byte-identical product files before archiving. The successful build and packaging commands used these exact paths and environment:

```sh
artifact_root=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/private-direct-format2-78429a9
source_root="$artifact_root/build/source"
export PATH="/tmp/peerwork-rustup/toolchains/1.89.0-x86_64-unknown-linux-gnu/bin:/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin:$PATH"
export CARGO_HOME=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-target/cargo-home
export CARGO_TARGET_DIR="$artifact_root/build/target"
export RUSTUP_HOME=/tmp/peerwork-rustup
export TMPDIR="$artifact_root/build/tmp"
(cd "$source_root" && cargo build --release -p peerwork-cli -p peerwork-node-native --offline --locked)
(cd "$source_root/bindings/python" && maturin build --release --offline --locked --out "$artifact_root/build/wheels")
export npm_config_cache="$artifact_root/build/npm-cache"
(cd "$source_root" && node bindings/node/scripts/package-platform.mjs linux-x64-gnu "$artifact_root/build/target/release/libpeerwork_node_native.so" "$artifact_root/build/platform")
(cd "$source_root/bindings/node" && npm pack . --pack-destination "$artifact_root/build" --silent)
(cd "$artifact_root/build/platform/agent-sdk-linux-x64-gnu" && npm pack . --pack-destination "$artifact_root/build" --silent)
python3 -m venv "$artifact_root/install/venv"
"$artifact_root/install/venv/bin/pip" install --no-index --no-deps "$artifact_root/build/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl"
```

The Node consumer had a newly written `package.json` with `name=peerwork-offline-consumer`, `version=1.0.0`, and `private=true`; from `$artifact_root/install/node` its exact install command was `npm install --offline --ignore-scripts --no-audit --no-fund --no-package-lock "$artifact_root/build/peerwork-agent-sdk-0.0.1.tgz" "$artifact_root/build/peerwork-agent-sdk-linux-x64-gnu-0.0.1.tgz"`.

The service invocation used `build/source` as cwd, the fresh state `build/private-direct-format2-state-1`, and these externally supplied guards:

```sh
artifact_root=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-artifacts/private-direct-format2-78429a9
PEERWORK_TEST_SDK_ROOT="$artifact_root/build/source" \
PEERWORK_TEST_STATE="$artifact_root/build/private-direct-format2-state-1" \
PEERWORK_TEST_NODE=/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
PEERWORK_TEST_NODE_PACKAGE="$artifact_root/install/node/node_modules/@peerwork/agent-sdk" \
PEERWORK_TEST_CLI="$artifact_root/build/target/release/peerwork" \
PEERWORK_TEST_DIRECT_COMPILER_SHA256=c356220b74e4407998d4ad2e84a7c0a159478a425f030c6989ee0e18dbdb02ef \
PEERWORK_TEST_PRIVATE_PRODUCER_SHA256=93237fde9e9ea7483b0631169d3983139fa17f75fdc0b53515ff318deffd7207 \
PEERWORK_TEST_RUNTIME_INSTALL_SHA256=098c066d6bf1ffce624c13ac9673fe1cda012478238d8c52b85b493cecfbff36 \
PEERWORK_TEST_TRANSITION_SHA256=09b440b27962e91c144a8de5ac997482175af4168d6fc297cbac127615cd044f \
PEERWORK_TEST_FIXTURE_SHA256=50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0 \
PEERWORK_TEST_VECTOR_SHA256=9e96c0eec94150d6b890c9988bec22272d338fa9a930d20e34a1ebfa34b2ddac \
PEERWORK_TEST_ROOT_DIGEST=3e14bcad26a11c7f9a09ce3099bdf4043f6d6ea50bac2463638cc3a79baf691c \
PEERWORK_TEST_PROTOCOL_DIGEST=a95f5fb783ad9e5bd04ef85e7b3f3cd7f084f19db07f287075210ce729cf9b72 \
PEERWORK_TEST_SOURCE_DIGEST=b792d58a1c33218f121d7c742ca85bf63c411ab3aa5733ff88cc8b919f05496a \
PEERWORK_REFERENCE_ROOT=/root/workdir/message/.worktrees/e2ee-main-integration-20261006 \
TMPDIR="$artifact_root/build/tmp" \
"$artifact_root/install/venv/bin/python" tests/installed-private-direct-format-two-smoke.py
```

Output was captured at `build/installed-private-direct-format2-try1.log`, SHA-256 `8c8c377b6c0a6445837cb4f64e8ccc924cf06e39cf2a534ba719335ce1c94944`. A native Owner created a PRIVATE STRUCTURED workspace, authored and verified an earlier encrypted wiki record, and activated the tracked protocol cutover. Python, Node, and CLI all rejected the format-two DIRECT selection while the signed policy ceiling was one, with no new service commit and no saved install row. Python submitted a signed ceiling-two transition; authenticated read and a test-only canonical policy/commit SQLite oracle checked its lineage and preserved Owner, membership, structure and earlier record.

The fixture then dropped a successful BEGIN response after applying it. A child Node caller withheld its generated BEGIN command ID; a fresh Python public `installs()` recovered exact saved ID `mabcjkMwsupgNVxmUrSX38tyH3aha13_5bLU3ycYYv0`. CLI and Python continued the saved operation through the observed distinct `PAGE`, `PAGE`, `END` command IDs and hashes; no duplicate commit occurred. Native verified read reached signed sequence 8, found DIRECT source kind with zero staged parts, signed format-two protocol digest `a95f5fb783ad9e5bd04ef85e7b3f3cd7f084f19db07f287075210ce729cf9b72`, composition source digest `b792d58a1c33218f121d7c742ca85bf63c411ab3aa5733ff88cc8b919f05496a` and its exact normalized manifest/dependency, and instance `q0QIzuxPhkHGPfRifyBk9hNZj9c63DbsOu3NkvdkeiY`. The earlier encrypted record `DR1wEGbaK8gCixhPE5PsSb2J3v8c-MPF5ApmW3miaZU` retained its exact title and body. Native typed `lib.replace` was accepted and its value read back; exact same-ID action retry preserved the accepted result and commit count. Repeated install continuation added no commit. With the service stopped, Python, Node, and CLI returned equal completed local install histories.

The SQLite oracle hashes canonical signed artifacts and binds their hashes/head/sequence to native verified reads; it checks signature-field presence but does not itself verify signatures. This is one scripted mixed-interface Linux x64 gate using the default raw closure/empty bindings and one Owner actor. It does not prove nondefault bindings, DIRECT distinct-member consume, independent end-to-end use in each interface, async cancellation, natural Agent workflow compliance, macOS/Windows execution, or lower-glibc dependency-closed packaging. The initial two Cargo commands failed before compilation because they used `/tmp/peerwork-cargo-home` (missing cached `base64`) and then default `/root/.cargo` (offline `tokio-macros` resolution). The succeeding build used the established task-local `.build-target/cargo-home`; neither setup failure changed the archive or product source.
