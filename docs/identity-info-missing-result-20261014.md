# Missing native identity diagnostics

Commit `41c4a98736cc8b92ff51415f229fb080fc34f524` adds a read-only missing-state classification across the CLI, Python, and Node identity-open surfaces. A missing identity file, or one absent configured state-directory leaf beneath a verified protected parent, returns `IDENTITY_MISSING` with the explicit config-aware legacy import command. These missing-state reads create neither identity state, the configured directory leaf, nor a lock. Unsafe parents, symlinks, and corrupt existing state remain `IDENTITY_STATE` failures; corrupt-file handling preserves the corrupt bytes but may use the normal protected-parent lock. The generic low-level store and import APIs retain their existing behavior.

The focused runtime test `kernel_identity::tests::missing_identity_is_classified_without_creating_state_or_lock` passed 1/1. An offline cross-crate check of `peerwork-cli`, `peerwork-python-native`, and `peerwork-node-native` passed. The CLI built successfully, and `tests/cli-relative-identity.py` passed against that binary, including missing-file and missing-leaf no-write checks, the missing → explicit selected-PEM import → public-info sequence, corrupt-state refusal, unsafe-directory and symlink refusal, and the existing source-permission checks. Python wrapper and test syntax checks, Node v24 `--check`, and `git diff --check` passed. The Node Rust binding was compiled.

The test and build results were returned as terminal tool output and were not captured to separate log files. The focused runtime test was execution session `55769`; the cross-crate check was session `2319`; the CLI build was session `34277`. The no-model CLI regression completed directly with exit 0 and printed `PASS relative protected identity import/create/info and strict source refusals`. The Node syntax check used the established Node v24 binary at `/root/workdir/message/.worktrees/peerwork-sdk-historical-direct-facades-20261014/.build-artifacts/historical-direct-873a37d/rootfs-managed/opt/node24/bin/node`. The retained no-model CLI regression is `tests/cli-relative-identity.py` (SHA-256 `97b558919ef027126ae6e7c54ac86a749a2aa31840e31b2fd2a8c8ab993fdb76`); its task-owned debug executable is `.test-data/identity-info-missing-20261014/target/debug/peerwork` (SHA-256 `f058a69867f2e6a3fc25b9d3ba8dcd70cbe94feac1f0bf1605b23a69873775b8`). No Windows runtime result is claimed.

Changed source hashes:

| Path | SHA-256 |
| --- | --- |
| `crates/runtime/src/kernel_identity.rs` | `7ecb142d410064d8463e94ff5bade113b5672916291bb17c1ddb15bcbb093e2e` |
| `crates/cli/src/main.rs` | `b2f2bd0023e766fa380d207f097d4f7602ea350a73fe26540a417f2118dbf3ad` |
| `bindings/python/native/src/lib.rs` | `ae81a14c84650a45d044fbce7016fdd789f909b69063cc58b58cb0530e9e1345` |
| `bindings/python/peerwork/__init__.py` | `d62e73203a97b7e676db86aaf229416f626d1fd9fc5bb5e4b0780842fb443956` |
| `bindings/node/native/src/lib.rs` | `ddab30723e55cca4a7275aa680ba33b4c5b9a9d1e73a1397f5f53222f3b90e57` |
| `bindings/node/index.cjs` | `36e9aa80b476c70c39c7efb1e20bfbd8fdf128cb9b32ed36845d8595d245e624` |
