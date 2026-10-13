# Installed orphan stage handoff on the glibc 2.28 baseline — 2026-10-13

This is a scripted, mixed Python/Node/CLI Linux x64 acceptance result on the
same immutable SDK archive. It is not a natural Agent workflow, an independent
per-interface flow, a macOS/Windows result, or multipart orphan recovery.

The SDK source was `git archive 1fbe859` at
`.build-artifacts/orphan-glibc28-1fbe859/sdk-1fbe859.tar` (SHA-256
`dc2d2a8703ecd904cc618dacf5c1ac106ad53e579a8b8baad45454ea095322ec`).
This archive includes the reviewed six-path Owner orphan facades at `5e5b326`
and original installed harness SHA-256
`ac5f1c99ef6692cf867d8f5d3a3d819117127f32627768d2080132b00b4a3774`.
The only later tested source was a separately pinned test-only split-fixture
overlay, commit `3028459`, SHA-256
`cbc12c0583e5b793e8a01c195b9e3247367d783b4a5d600c20e30a5d9e889bbc`.
`git diff 1fbe859 3028459 --name-only` lists that test and a documentation
file; the native product files stayed byte-identical. The overlay changes
fixture orchestration only; the business assertions are the same.

The already verified pinned manylinux glibc 2.28 rootfs and Rust/GCC/Node
toolchain are attributed in `docs/distribution-spike-20261012.md` under the
glibc 2.28 section. Build command from the SDK worktree was
`bash .build-artifacts/orphan-glibc28-1fbe859/run-build.sh .build-artifacts/glibc28/bundle/rootfs`;
the runner SHA-256 is
`568c8f525a9f6aee2ab499554c7338bcb4c7adf1714132ca4a6322b51a5f98e7`
and its chroot script `/work/sdk-orphan-1fbe859/build-current.sh` SHA-256 is
`e636b07907b08db50dca691ac8a698bc9ed142539bde7df8049e5ac4949f2b82`.
Build session `60968` exited 0; `build.log` SHA-256 is
`29c69a771b534fa373d67cbe2ab8f64459ba9620ed99b7cbf415a9da9deaa72e`.
`CARGO_NET_OFFLINE=true` and the task-local copied target were used. The
source archive and prior artifacts were not rebuilt during test-only fixes.

Artifact paths and eight full SHA-256 values are in
`.build-artifacts/orphan-glibc28-1fbe859/manifest.sha256` (manifest SHA-256
`a58463e6b890441fabe8f8c768e72c571f72216310f39aaa85b38a259be8ce50`);
`sha256sum -c` passed all entries. The wheel is
`dist/wheels/peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl`
(SHA-256 `1cc86214748a838e29b9ae378dc54a9d42f912fae16a43bc277a4e65f4564706`),
the CLI SHA-256 is `f886b5686b7506aa44bede869f0cf06b0ad7c0c78960d6d6f3e08fe4529ea033`,
and the Node addon SHA-256 is
`2a05f97bc41151e3a7663a4cb1f285d560982da6624684710a16ade16259276a`.
The npm facade and GNU-platform tarballs, plus installed addon/extension
hashes, are in that manifest. The wheel's `py.typed` marker verifier passed.
Raw ELF `NEEDED` output is `elf-inspection.txt` (SHA-256
`e67572981d8723dcd9f30da83b5c396fd8c2e74e60e26fb4d7842186c61a6a48`);
`elf-versions.txt` (SHA-256
`1aa89873454e1330cd5f15cc155217bee0c0adaf608555f2c050ce2659b1f205`)
shows CLI, Node addon, and installed Python extension each require at most
GLIBC_2.28, GLIBCXX_3.4.11, and CXXABI_1.3.8. They depend on the baseline
system `libstdc++`, `libgcc_s`, and glibc; installed consumers did not use the
build-only `LD_LIBRARY_PATH`.

The chroot packaging script
`/work/sdk-orphan-1fbe859/install-current-inner.sh` (SHA-256
`80410c4cec24e0b162f37ab4633cffaba1727778b00d97b5022ad84cf4596e4c`)
used `npm pack --offline`, `npm install --offline --ignore-scripts`, and
`pip install --no-index --no-deps --target` into fresh consumers. The first
sandbox invocation failed before those commands because `unshare` could not
write `uid_map` (`install.log` SHA-256
`731fa347449bfb63ad97dd72dadf5ae4776694f1365e5638d81b7860c7819cfd`).
The approved local invocation session `18523` installed both npm tarballs
and the wheel and imported the Python and Node packages. Its final ad hoc
`peerwork --help` probe returned exit 1 and `USAGE`, so the whole script
exited 1 (`install-approved.log` SHA-256
`041e8037e6253aff0aac1c99a2cabfd3752c886d1f1fd4d428c85844eee1367f`).
The documented `peerwork version` command later exited 0 inside glibc 2.28;
`--help` is an unresolved CLI discoverability/ergonomics issue, not evidence
of a failed package import.

The first installed harness session `60567` reached the old-client fixture
before any native attach, then failed `SECURE_LOCK_IDENTITY_UNAVAILABLE` because
the isolated rootfs had no `/proc/self` (`installed.log` SHA-256
`8443c73bd7a47f1fcbe6ae380911eb128b0144f1cc0ae616e17b8525b3956de7`).
A private proc mount was denied (`installed-proc.log` SHA-256
`4355f446697f26bb62f81fd8fd2f924fc37a5a82650323f0a591bdf1fac75451`);
automatic approval review rejected binding the host's entire `/proc` because
that would expose unrelated process metadata. No host proc bind or source lock
bypass was used. Source review also found the first split-runner draft had
not pinned generated client modules and incorrectly named old `ae5d115`
as the stage-marker client. These were pre-run runner defects: the actual
stage-marker API comes from current reference `f828b6c`.

The corrected host runner
`.build-artifacts/orphan-glibc28-1fbe859/host-fixture-run.py` (SHA-256
`489975bc0c4cf24aec059ef58dc9b8c5d6fe5170bec529f448d84c496d5c2d30`)
archives tracked `f828b6c` into a fresh task-local directory, checks the
installed/locked TypeScript 7.0.2 native compiler and full platform package
tree, recompiles there, and requires the five known generated-module hashes.
Its full 204-JS-file generated tree SHA-256
`e45fa95c3f7ae25723f8175dd471b662020d81266db34fa96b12133fe4bf1afb`
matches the reference service's generated tree. It validates the complete
observed bare-import set and exact locked versions/file trees of all 12
runtime packages used by helper and service, including Hono and markdown-it
transitives. The passing log records the compiler, generated output, and
dependency-tree manifests. The host service and helper use this guarded
`f828b6c` source; only the three task-created protected source path strings
are mapped to the rootfs's `/work/sdk-orphan-1fbe859/dist/orphan-state-split`.
The SDK consumer runner `run-consumer.sh` SHA-256 is
`922e98c7ee0a658057ecf732034ae04ff94957d6aad715a777460a94fc2b3575`.
It does not mount `/proc` or substitute host SDK packages.

The exact passing command was
`python3 .build-artifacts/orphan-glibc28-1fbe859/host-fixture-run.py .build-artifacts/glibc28/bundle/rootfs`.
Session `44554` exited 0; `installed-split.log` SHA-256 is
`fb631effa7f95dd4ce56952ce3b8600aab012d0c63e21916c48ca86f0eea71f7`.
The installed Python/Node/CLI calls ran inside the glibc 2.28 chroot against
the host's same-network-namespace loopback reference service. The selected
PRIVATE wire-v3 one-part orphan marker had no saved POST: workspace had one
bootstrap commit and the original marker command had zero. Public inspector
IDs/digest, Python/Node/CLI status, wrong digest/ID refusals, and three
`ORPHAN_STAGE_UNRESOLVED` selector refusals were asserted without extra
commits. After moving old source files away, native read was authenticated
online; attachments history remained local. The explicitly selected new
stage POST applied despite a lost CLI reply. Public saved IDs led to exact
no-material continuation and signed part readback. Exact retry and changed-ID
conflict left sequence and commit count at 2; the original marker command
remained unposted. The log records the public workspace, original/new command,
source, and stage IDs without keys or packet contents.

This establishes one scripted installed orphan handoff and the Linux x64
glibc 2.28 dependency ceiling. It does not establish natural Agent instruction
compliance, publisher/catalog discovery, independent full Python/Node/CLI
workflows, offline authenticated service reads, multipart orphan recovery,
or macOS/Windows package execution. Those remain separate acceptance gates.
