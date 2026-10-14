# ARM64 musl release artifacts and emulated installed results

The release CLI, Python wheel and npm platform addon were built from accepted SDK product base `3605a3c764f07f75ae86602ffbf3e0915ff2aeac`, with build-source checkpoint `a3ba77a23877c2d488f0e5dd6ab6db36a9ef4e55` (documentation only above that base). All three installed interfaces passed their actual scripted HTTP flows under ARM64 user-mode QEMU. The CLI is fully static: ARM64 ELF, no interpreter and no dynamic section. This closes the bounded local artifact/emulation lane; it does not establish native ARM hardware execution or the whole release/Agent plan.

Final product checkpoint `4d6093205c363f06729d825cc55a92bbbd221079` adds the musl architecture matrix and a separate minimal runtime CI consumer. `Cargo.toml`, `Cargo.lock`, `crates`, `bindings` and `third_party` are byte-identical to accepted3605 (`git diff --exit-code` passed before that commit). CI source SHA-256 is `655f84304dc671ce6165007fe37cd5d5b2d666beebd7447c83ac814c063748de`. The matrix names native x64 and ARM64 runners; no GitHub run or native ARM execution is claimed. Local host is x86_64, kernel `6.12.90+deb13.1-amd64`; QEMU binary SHA-256 is `73cc2584f119f9e74c85c0a8549dbb6fd104ae3897a06a7500797f9e5b4d0943`.

## Deliverable artifacts

Paths below are relative to this isolated worktree, `.worktrees/peerwork-sdk-arm64-musl-release-20261014`.

| Artifact | Path under `.build-artifacts/dist/` | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| Static CLI | `peerwork-linux-arm64-musl` | 18,146,552 | `f2c373a58c0a38094d4ad18df80ba6f65a637c58f5e76ab1a869f653abf09e62` |
| Python ABI3 wheel | `wheels/peerwork_sdk-0.0.1-cp311-abi3-musllinux_1_2_aarch64.whl` | 8,203,342 | `751a8e58d8c66c4d97a3e451a30eaa96c8d9bf8b9c1180f7cfa0e50a21e81795` |
| npm frontend | `peerwork-agent-sdk-0.0.1.tgz` | 20,516 | `c4b67c8de913506b4d44ad2e4bbb3d58dc06888ab94a7d234fd5d215810f0e83` |
| npm ARM musl platform | `peerwork-agent-sdk-linux-arm64-musl-0.0.1.tgz` | 8,109,189 | `229b032fdb9603e7eec9aea7e80bdb227b77fd3c879caa717f97b1e07b5d52de` |

Full package-file and evidence-log manifest: `.test-data/arm64-release-artifact-manifest.json`, SHA-256 `7db16f9f33fcab41f05ffd9f5af6a55dd19de94c25c76f26a267d875a713cbb4`. All artifacts remain local; nothing was published.

## Measured dependencies and provisioning

The CLI requires the supported ARM64 Linux kernel/ABI and no shared userspace libraries. It ran through the static QEMU executable without `-L`, guest sysroot or `LD_LIBRARY_PATH`. This is a scoped Linux ARM64 result, not a universal operating-system claim.

The Node addon requires musl and three bundled LLVM 20.1.8 libraries (`libc++.so.1`, `libc++abi.so.1`, `libunwind.so.1`). Addon RPATH is `$ORIGIN/lib`, with bundled-library RPATH `$ORIGIN`. The Python extension requires musl and the same three wheel-bundled, hash-renamed libraries, with extension RPATH `$ORIGIN/../peerwork_sdk.libs`. Neither SDK addon has a GNU C++/libgcc or external ICU dependency. ICU78 source/data remains statically embedded; LLVM licenses are included. Actual ELF metadata for nine SDK outputs/bundled libraries is recorded in `.test-data/arm64-release-dependencies.json`, SHA-256 `7be853b817369dadfe77d21b260ecf6031882d3ef4a2360409a67abf2f6f2f2c`, and `.test-data/arm64-release-elf-audit.log`, SHA-256 `b0a1972fba07a00704f8b81102c5e4773c79aaed27b45d6a0f6f571a8c737f8a`.

The separate minimal runtime root contains Alpine ARM musl, Python3.12.15 and Node22.23.2 with their signed package dependencies. Node's own GNU C++/ICU76 dependencies are host-language dependencies, distinct from the SDK's LLVM/embeddedICU78. Before SDK installation this root had no LLVM C++/ABI/unwind shared libraries or compiler/development packages. Guest wrappers clear inherited library/Python paths and use only the runtime root's loader/search paths. Installed Node reports `arch: arm64` and loads the platform addon from its installed npm package. Python `-I` reports `aarch64` and the installed ABI3 module path within the runtime root. The ABI3 tag promises Python >=3.11 by build configuration; actual ARM execution here used3.12, not3.11.

Provisioning input pins and exact39 package versions/dependency metadata/signature results are in `.build-artifacts/provision/verified-packages.json`, SHA-256 `da0485dad63e6f08e49a664dbf81d411e977518687da10a952289a60a8cfde40`. The downloader independently verifies the pinned index SHA/signature, exact plan rows/URLs, Q1 control-gzip hashes and package signatures. Post-guard archive-to-extracted-payload reconciliation covered1,979 runtime paths and953 new build overlay paths: `.test-data/arm64-extracted-input-reconciliation.json`, SHA-256 `336b70fec504bb12d9646cf0afd47565ffd6379e149968c33822b2ae5d99700f`. Existing copied cross-toolchain files retain the accepted prerequisite pins; regeneration is not claimed. Existing LLVM shared runtime source files were additionally matched to their pinned signed archives and the trusted index at `.test-data/arm64-existing-llvm-runtime-reconciliation.json`, SHA-256 `fe7d4029b765fff4e790d9f4e9f5e6c7d1db0abc6a645363250efadf64cf3ca8`.

## Actual gates

Rust1.89.0, locked offline Cargo and task-owned output/cache/sysroot were used. Static build environment is recorded in `.build-artifacts/static-build-env.sh`. The shared builds use `-C target-feature=-crt-static`, the same verified target/ICU inputs and ARM3.12 sysconfig metadata. Maturin1.15.0 repairs/bundles the wheel; the existing platform packager bundles the npm LLVM libraries. Host pip/npm explicitly cross-install these artifacts; installation alone is not counted as ARM execution.

| Gate | Authoritative handle and result | Evidence under `.test-data/` |
| --- | --- | --- |
| Release static CLI build |76319, exit0,5m42 |`arm64-static-cli-build.log` (`5da6d3d3110ab676bcd8830853a0405ae0452a0a22f02991543b395b75b65d2a`) |
| Shared Python/Node release build |31601, exit0,6m50 |`arm64-shared-bindings-build.log` (`6c4d53fe83a9254940aeef9f0102ce51f822d0fcaeadf812715fdaf8442ff02e`) |
| Corrected canonical wheel packaging |21002, exit0,44.63s incremental compile |`arm64-wheel-package-canonical.log` (`7c9afba706155b8238225227f968ed3f4cec3cbc26f0046c58c50810f12c4f08`) |
| Installed guest Python/Node loads |39242 and78533, exit0 |`arm64-wheel-installed-qemu.log`, `arm64-node-installed-qemu.log`, `arm64-node-installed-paths.log` |
| Independent identity creation + cross-interface reopens |83442, exit0;3 creators ×3 reopens |`arm64-installed-protected-identity.log` (`e985a62ae0745fac39d6ff793f037dabd9ba23419f80454a90e46b96cbeb56cd`) |
| Static release ICU locale vectors |98466, exit0; exact test1/1 passed0.04s after31.24s compile |`arm64-static-icu-locale-qemu.log` (`73be5686418ade90d0517d096ddc3e44458a2062b696a0c19b36401a8d978295`) |
| PUBLIC signed action/lost-response/recovery |98852, exit0 |`arm64-installed-public-http.log` (`62c9d09336261bdc8bf76af703aa1d731b978999dec4fcfe1fff975d32aae29c`) |
| Independent PRIVATE Owner/E2EE/catalog/install/action/readback |70763, exit0 |`arm64-installed-private-http.log` (`efa99fd7cc66f77a775690138b8ae0b6110a56fe3a6a9bd3f872b2dbab935897`) |

PUBLIC preserves the existing three-interface assertions: Python, Node and CLI each submit a command whose response is dropped, recover the exact saved ID, verify the signed receipt/readback and retry without another accepted effect. Final service state is4 commits, sequence4 and3 records. PRIVATE preserves the existing independent interface test: each interface creates its own protected Owner/workspace, inspects the exact catalog bundle, selects the pinned binding digest `ab2a4c9c6cd39884796c7e8f4196c9925b2e2e06db3a13ca6ac07f9eaf362f35`, installs, submits/reconciles an encrypted action, retries without another accepted effect and verifies final sequence5/counter1. Host services/count oracles are separated from guest SDK calls; consumers do not read hidden native storage. Reference service is exactf828 (`f828b6c50a0a58d1e718af90f653b214adcc3328`). All owned service/build handles are terminal; services were closed by their owning adapters.

The reviewed task-local host adapter `.test-data/run-arm64-installed-http-host.py` SHA-256 `ab38286a30b05f1db42aa86e3e78f723c995f981b924ea7ad387a5af87672a7e` starts only reference services with host Node and runs the unchanged PRIVATE test using guest consumers. PUBLIC adapter `.test-data/installed-arm64-public-action.py` SHA-256 `9ca52643e42309200515c6b733d12e71340ae1f21b18895dba04eaffa4215223` changes only the host service Node selection. No business oracle was weakened. Other Cargo test binaries selected zero tests under the exact locale filter; they are not additional passes.

## Workflow evidence and retained deviations

These are scripted SDK business tests, not a natural Agent acceptance run; entry-instruction/protocol compliance by an Agent is unverified. The actual source-reviewed HTTP tests passed on their first executed package inputs. Provisioning and implementation first-attempt compliance had these corrections, kept separately from business correctness:

- Index verification initially used the wrong x64 keyset, then relative ARM key paths; both returned `UNTRUSTED`. Absolute trusted ARM keys/index paths passed; no untrusted bypass was used.
- Scratch APK DB simulation failed before a verified rootfs copy; the copied default repository list then emitted network IO warnings under `--no-network`. Exact local index resolution selected packages; local fetch URL lookup failed because the archive files were not yet present. Download/verification then passed.
- Extraction finished before the reviewer found the downloader lacked an independent plan-to-index assertion. The corrected guard and later unchanged-payload reconciliation passed before any SDK build. Earlier extraction is not retroactively attributed to the corrected guard.
- First wheel invocation spelled the same sysroot with `/../../`, changing exact Rust flags and triggering avoidable compilation. Its owned process tree was cancelled (34805, exit143) after diagnosis; canonical packaging then passed. `.test-data/arm64-wheel-package-path-correction.json` preserves the action. Cross-wheel logs also retain foreign-ELF compiler-probe/relocation warnings from host tools while target library paths were present; final ARM dependency audits and clean guest loads passed.
- Initial Node packager hit sandbox `spawnSync patchelf EPERM` although its child returned0. The unchanged bounded packager passed with normal subprocess access. Host cross-install uses npm `--force` to select ARM packages on an x64 installer; actual guest platform detection/loading is independently observed.
- Initial YAML validation lacked a parser; task-local pinnedPyYAML6.0.3 then parsed both matrix rows and expanded shell syntax. A draft-edit assertion failed without changing the file; subsequent source correction passed. A reviewer initially attributed the146 draft to invoking pip inside a `--without-pip` venv; that finding was withdrawn because the actual source used system pip with `--prefix`. No CI runtime failure was observed. The root-requested final consumer instead derives venv `purelib` using its own `-I` interpreter and system pip installs directly there. Source review is separate from unexecutedCI.

## Remaining plan coverage

Accepted native migration behavior includes completed direct maps, retained exact BEGIN/PAGE/END packets, selected same-workspace intents, original checkpoint verification and disclosure/omitted-grants normalization with protected v1/v2 recovery. This ARM package preserves that source; it does not repeat or extend those historical native gates.

The next migration package must address an ordinary still-refused public source family, using the existing signed BEGIN/current-authority verifier and normalization rather than recreating migration scaffolding. Composition/dependency selections, staged/object install sources and remaining historical dispositions remain required. A bounded exactf828 source audit will select the next source family by its real public install flow and reuse existing fixtures/verifiers; design and genuine source evidence precede product changes. Native ARM CI execution, Windows/macOS runtime evidence, remaining installed optional-option combinations and reliable Agent entry/workflow acceptance remain separate open plan items. No whole-plan completion is claimed.

The existing public-interface release audit must also correct capability metadata with precise scope: the tested artifacts still return `verified_workspace_reads:false`, `safe_actions:false` and `durable_recovery:false` despite these supported bounded public/Owner flows. Preserve that observed metadata mismatch and advertise exact supported capabilities before release; these results do not justify blanket true flags for unverified behavior. This report-only follow-up leaves artifact bytes and their evidence unchanged.
