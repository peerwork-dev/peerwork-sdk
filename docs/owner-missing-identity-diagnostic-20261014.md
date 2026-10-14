# Missing configured Owner identity

Corrected product `0188b7ec1368e3f56fbd1137b3dd02cbb093a6af` (predecessor `df4be4a954f5a4cfc0f65f35a8cb42ec3fa6e669`) is isolated from main `c37c4ce` in `.worktrees/peerwork-sdk-owner-missing-identity-20261014`. It corrects the distinct error observed in preserved natural-Agent `50484`: Owner read and operation discovery returned `IDENTITY_CHANGED` although the actor had never imported or created `state_dir/identity.state`. The proxy diagnosis does not change that failed workflow result; no new actor was launched.

Six Owner identity-open callsites now share one classifier. Missing native identity under an existing protected state directory returns `IDENTITY_MISSING`. An absent configured state directory is classified as missing only when its existing parent passes the same private-parent validation used by protected state. The static error supplies the config-aware legacy import verb and asks for the selected Owner config and protected PEM; no actual path, key or content is included. Existing corrupt, loose, symlinked, busy or otherwise inaccessible identity errors retain `IDENTITY_CHANGED`, and saved origin/actor/key mismatch remains `IDENTITY_CHANGED`. The read/open path creates no identity or absent profile directory. Historical attachment's selected PEM import and trust checks are unchanged. Participants still select their identity and source explicitly; the platform does not manufacture an identity or weaken protection to make a read succeed.

The source delta is limited to `secure_owner_create.rs`, `secure_state.rs`, `windows_fs.rs` and the existing `tests/cli-owner-identity-config.py`.

Predecessor df4 targeted Rust 1.89 locked/offline CLI build `66081` passed in 55.66 seconds, with task-specific copied Cargo cache/output, log `.build-target/build.log` SHA-256 `f06824a188a835a23b44c7f5f4db188ab23ad01bdd0df8c8187119660ea26d15`. Preserved predecessor binary `.build-target/identity-before-integration-peerwork` SHA-256 `106824f18fa822af331a2ea40453df37ae4196c238c29e25f45868081899a9a3`. `python3 tests/cli-owner-identity-config.py .build-target/target/debug/peerwork` exited 0 (0.476 seconds), log `.build-target/identity-cli-regression.log` SHA-256 `d2cd0648e7c44fa44620db1a7523b57aecfa290706454ff1c7f83fc4f3b9411f`. Source-pinned assertions cover missing directory for both Owner read and operations without directory creation, wrong imported filename as missing, configured import/public IDs and subsequent operation discovery, corrupt/loose/symlink identity refusal without rewriting, absent state under a loose parent retaining the old refusal, and no PEM/seed output. The single PASS line has the prior test's wording; its identical hash is not independent proof of the new assertions without the source pin and actual command result.

The focused Rust regression `63168`, `cargo test -p peerwork-runtime --lib owner_missing_identity_is_distinct_from_saved_identity_mismatch --offline --locked`, passed 1/1 in 0.11 seconds after a 23-second test build. It opens no network service: missing native identity returns the new code, a protected history bound to the selected identity reads successfully, and replacing that identity with another valid native identity retains `IDENTITY_CHANGED`. This is local classification/history-binding evidence, not signed service or installed Python/Node proof. `py_compile` and `git diff --check` passed.

This fixes the actionable missing-identity error at the product boundary. It does not establish that an Agent will perform the import, discover pending IDs, follow the protocol or finish an installation. Natural-Agent business/workflow, immutable release rebuild, public distribution, supported-platform execution and the remaining full plan are still open. Prior attempts and the separate proxy harness timeout remain preserved.

Focused Rust log SHA-256 `389fd4a002a960bf055c954b4b73e45ba5200f01a6d8d625fcca9b4016d3daee`.

Review caught a predecessor Windows side effect: the initial absence helper called the existing parent check, whose Windows implementation may create its missing parent. Linux passes did not establish the claimed behavior on Windows. Successor `0188b7e` adds `private_existing_parent`, which validates existing handles/DACL/reparse ancestry using OPEN_EXISTING without creating a directory, and refuses absent or unsafe ancestry before ordinary identity open. Its focused new missing-parent regression checks that Owner read/operations leave an absent parent absent. Windows execution remains unverified; this correction has source review and Linux regression only.

Corrected secure_owner_create.rs SHA-256 `42fee9c13c9b0a4b5d4e9fcb48e08f849df010969802751b3c76ef736236f4d7`.

Corrected secure_state.rs SHA-256 `d903995911f2bcbaa12c37ef27b93a8447236ed79058cd4b988f8792a5cbe163`.

Corrected windows_fs.rs SHA-256 `f064763f3a14e2633e71c6c9e20c9d85c19e5e2eee50d177ac9622d5ba2464a0`.

Predecessor df4 binding check `22695` (`cargo check -p peerwork-python-native -p peerwork-node-native --offline --locked`) exited 0 in 3m15s, log SHA-256 `a068ff2e0f43855933c32949f36555780ab61e78b3dd1832cb8fbd7da9ff8400`. This is Linux compile evidence, not installed binding or Windows execution.

Corrected source `0188b7e` regression `1821` passed 2/2 in 0.08 seconds after a 12.69-second test build. It includes the new absent-parent check for Owner read/operations and retained saved-identity mismatch semantics. Log `.build-target/identity-corrected-test.log` SHA-256 `e2fd90658833c30a6536b8a97ec33c56c5f176baf45f4175c0099cc456dc94ff`. No Windows runner was used.

Combined handoff source `06667a705f36f9da13aa6d2782eb4d65b77ab766` preserves main c37 completed-map and facade bytes (`secure_owner_attach.rs` has no delta), plus the byte-identical accepted proxy paths. Incremental CLI build and four-crate runtime/CLI/Python/Node compile `11588` passed; the final CLI missing-identity regression exited 0, exact-policy proxy regression `92691` exited 0, and focused integrated runtime `91867` passed missing-identity 2/2 plus explicit proxy selection 1/1. These repeat only interacting checks for the merged source. The earlier signed-inspect result `47947` is reused in its recorded source scope; no signed fixture, release artifact cohort or natural Agent was rerun. The integrated debug binary is a local verification artifact, not a rebuilt release package.

| Integrated artifact | SHA-256 |
| --- | --- |
| `.build-target/integrated-build.log` | `cd2afdc937fac8a5fb1d1a86b3684e7db3089e7bb161ea5200cb8ae011afc555` |
| `.build-target/integrated-check.log` | `560be8cf5c5eec43a164b5fb701b11c85f722296851dc5a7e31647df305ce5b5` |
| `.build-target/integrated-identity-cli.log` | `d2cd0648e7c44fa44620db1a7523b57aecfa290706454ff1c7f83fc4f3b9411f` |
| `.build-target/integrated-proxy-cli.log` | `51e1c377031429ad582f46218d6422010b595859bd1e5402d698a7e695679ef0` |
| `.build-target/integrated-identity-test.log` | `aa7652b610576d3d20031b2b7b8134ebaa52939b7868a3780b1d46f6cd72e027` |
| `.build-target/integrated-proxy-test.log` | `1cc5d0e8e0ccb01d073a666c666519264b33230535baa265d56344083f74018c` |
| `.build-target/target/debug/peerwork` | `7d56f84a1798213d913b5e125b6c07ee44c1d375efb2fbd62783d23766fe0744` |
