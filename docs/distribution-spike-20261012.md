# Native distribution spike, 2026-10-12

This checkpoint validates packaging only for version/capability introspection.
It is not a functional SDK acceptance result. The core's cryptographic and
wire primitives are in progress, while verified reads, actions, and durable
recovery are marked false in the manifest.

## Local Linux x86_64 observation

| Check | Command or observation | Result |
| --- | --- | --- |
| Rust workspace | `cargo test --workspace` after dependency fetch | Exit 0 for initial scaffold; subsequent core edits require fresh tests |
| CLI | `cargo build --release --offline --locked -p peerwork-cli`; `env -i PATH=/tmp /absolute/path/peerwork version` | Exit 0, version `0.0.1`; 502 KiB binary at checkpoint |
| Python | `maturin build --release --offline --locked`; venv `pip install --no-index --no-deps dist/wheels/*.whl` | Exit 0, cp311 abi3 manylinux_2_34 wheel, 243 KiB |
| Python import | venv with PATH containing only its `bin`; `shutil.which` confirmed `gcc`, `rustc`, `cargo`, `node` absent | Exit 0; `version()` and `capabilities()` loaded from wheel |
| Node package | npm pack facade and Linux x64 GNU addon; `npm install --offline --ignore-scripts` from exact local tarballs | Exit 0; addon package 240 KiB |
| Node import | Node 24.20 with PATH containing only its `bin`; shell `command -v` confirmed `gcc`, `rustc`, `cargo`, `python3` absent | Exit 0; version and manifest loaded from `.node` |
| Missing Node platform package | Install facade tarball with `--omit=optional`; import it | Explicit `Missing @peerwork/agent-sdk-linux-x64-gnu native package` error |
| Binary dependencies | `ldd` on CLI, Python extension, Node addon | libc, libgcc_s and ELF loader; no OpenSSL library |
| Path handling | Offline Python and npm installs plus CLI run under `/tmp/Peerwork Install α/` | Exit 0 for all three version/manifest probes |

The first Node smoke used a file dependency that npm symlinked to source. The
facade then resolved from the source directory and could not find the installed
platform package. We switched the consumer test to packed tarballs, matching
the release format, and the same offline import passed. A Node script attempting
to spawn npm was denied by this local sandbox (`EPERM`); the final test invokes
npm directly and uses a pure-import smoke script. The first offline maturin
attempt lacked a newly added crate in the local Cargo cache; approved-network
`cargo fetch --locked` populated it and the offline wheel build passed.

## Remaining distribution gates

The GitHub Actions workflow defines representative real Linux, macOS and
Windows runner builds. The first push attempt failed because HTTPS Git found
no write credential; an SSH read probe returned `Permission denied (publickey)`.
No remote run is claimed until a write connection is provided, the workflow is
pushed, executed, and logs/artifacts are reviewed. Intended arm64/musl and Python/Node
runtime variations need separate execution before support minima are frozen.
The manylinux_2_34 tag is an observed Linux wheel result, not a declared
minimum. Signing, reproducibility, SBOM, public registry download tests,
protocol parity, operation recovery, and cold-start Agent acceptance remain
open. No production package publication is authorized by this checkpoint.

## Later Linux identity package check

After the initial version-only spike, the native identity parser correction
was committed as `e3b961a` and `67165fd`. Rust 1.89 focused identity test
passed. A task-local Cargo registry copy under ignored `.build-target/cargo-home`
allowed a locked offline `maturin build` without writing to the read-only
shared registry. The resulting development wheel is
`peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_38_x86_64.whl`, SHA-256
`241aba26fb1165028325ac1fafaf885df8f8010c318b6c5377aa137c6f229526`.
It installed into a fresh target with `pip install --no-index --no-deps`
and no build step; sync and async identity create/open plus repeated-create
refusal passed from that installed target. The Node 24 optional-package-shaped
development addon SHA-256 is
`8962c3bc035db7ff3017142ec90a39612028953ad4f43e8d7fec19a11b73e51b`;
Promise create/open and repeated-create refusal passed on a Unicode path.

These hashes identify local artifacts, not reproducible release inputs: the
core private replay source was modified concurrently during their builds, so
its exact source snapshot was not frozen for these two outputs. Both artifacts
need rebuilding from a committed tree before release qualification. The
measured manylinux_2_38 tag is not the supported Linux minimum, and neither
artifact was run on macOS or Windows. The restricted sandbox initially timed
out during Python async smoke; a standard-library-only
`asyncio.to_thread(lambda: 42)` timed out there too, while both it and the
installed wheel's async calls passed via the approved thread-capable route.

## Windows ICU source-build candidate (`b388755`)

The target-native x64 MSVC branch now verifies the pinned ICU 78.3 source
archive and embedded-data SHA-256 hashes before extraction. It transforms the
archive's `stubdata`, `common`, and `i18n` Visual Studio projects to static
libraries, adds `U_STATIC_IMPLEMENTATION` and `_78_peerwork` symbol suffix
definitions, builds them with the detected native MSBuild, and links those
libraries into Rust. The Linux/macOS configure path remains intact. This is
source support only: no MSVC compiler, Windows linker, installed artifact, or
Windows runtime was exercised here. The branch explicitly accepts only
`x86_64-pc-windows-msvc` and requires HOST==TARGET.
The committed `build.rs` SHA-256 is
`e24cf89f284d3b1f564b4f80ae423b0bd75d0c4067eacc2454c672654ecba4a5`;
the workflow SHA-256 is
`321b9436960c53bba809385218625160385900230b4f92d18ab985378cc39c0f`.

Local Rust 1.89 `cargo check -p peerwork-core --offline --locked` passed twice
with `CARGO_HOME=.build-target/cargo-home` and the existing task-local target.
A fake-MSBuild execution of the Windows branch against the exact extracted
archive passed all three project transformations and emitted the expected
static link directives. It created placeholder `.lib` files solely to inspect
the build-script path, so it is not compilation evidence. The first dry run
extracted into `/tmp`, hit `ENOSPC` before MSBuild, and its exact 44 MiB
task-owned partial tree was removed. The corrected dry run used task-owned
workspace output and removed its 122 MiB extraction afterward. No unrelated
cache or fixture was deleted.

The Windows workflow now requests the 28 pinned Node 24/ICU 78.3 collation
vectors with `ICU_DATA` unset, then checks built CLI, wheel `.pyd`, and Node
addon PE imports for dynamic ICU DLLs and probes Node Intl comparison before
and after addon import. Those workflow steps have not run. A real Windows x64
runner must still establish MSBuild compilation, FFI symbol consistency,
static linking and dependencies, embedded-data behavior, installed
Python/Node/CLI APIs, protected filesystem and cancellation semantics. The
workflow's other platform/runtime variations and release gates remain open.

## Native musl environment check

This host has no `podman`, `nerdctl`, `musl-gcc`, musl loader, local Alpine
root filesystem, or Docker socket. A task-local Docker 29.8 CLI is present;
its default sandbox probe returned permission denied, and the authorized
unsandboxed probe returned `dial unix /var/run/docker.sock: connect: no such
file or directory`. No local native musl build or installed-interface test was
run. A cross-compiled binary on this glibc host would not establish native
musl runtime behavior. The declared musl platform packages still require
target-native build, install, and API tests in a provisioned environment.

## Native Alpine musl package checkpoint (2026-10-13)

The earlier “no local native musl” finding above is superseded for x86_64 by a
task-owned Alpine 3.22.6 minirootfs run under `unshare --user --map-root-user
--mount --pid --fork` and `chroot`. This is native musl execution, not
cross-compilation or emulation. The official minirootfs archive SHA-256 was
`27694aaa55fd7a9e3ef596e0ad4eb66802308bb20172b17030cd5f4d8ae9bac2`;
the official Rustup installer SHA-256 was
`331228566cc931f32cd684f9bebc5956a5e5d7394c8d5de595f196a658ab98e6`.
Rust 1.89.0 `x86_64-unknown-linux-musl` ran from the isolated rootfs; Alpine's
Rust 1.87 was below the SDK MSRV. The installed native build packages included
Alpine `clang20`, `libc++`, `libc++-dev`, `llvm-libunwind-dev`, `patchelf`,
Python 3.12, and Node 22. The namespace bound only host `/dev/null` over the
rootfs mountpoint; it did not mount the host `/dev` tree or operator state.

The SDK input was immutable `git archive 21aa3038184eb6c963edb329510b46295f907c09`
under `/work/sdk`, plus only the committed musl ICU change `0d714ae` in
`crates/core/build.rs` (SHA-256
`a738f3fdc095d052177fae8a627bdbe5ef8dcba2b371e2db678617203d2bab8d`).
The package scripts and LLVM notice overlaid that archive from commits
`28f9dd7` and `da3f3a7`; the repaired artifact source did not include later
core/action worktree edits. The LLVM 20.1.8 notice was taken from the official
`llvmorg-20.1.8/llvm/LICENSE.TXT` source, SHA-256
`8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`.
The `build.rs` musl branch compiles pinned ICU 78.3 with `clang++-20` and
`-stdlib=libc++`; Linux GNU and other platform branches remain separate.

With `CARGO_TARGET_DIR=/work/target-libcxx`, native Alpine
`RUSTFLAGS='-C target-feature=-crt-static' cargo build --release --offline
--locked -p peerwork-python-native -p peerwork-node-native` passed. The pinned
Node/ICU collation regression
`cargo test --offline --locked -p peerwork-core
js_locale::tests::pinned_node_locale_compare_vectors` passed 1/1 on musl.
Clean Python extension import under Alpine Python 3.12 and direct Node addon
import under Alpine Node 22 passed without `LD_PRELOAD`. The shared extensions
have `libc++.so.1`, `libc++abi.so.1`, `libunwind.so.1` and musl dependencies;
no `R_X86_64_TPOFF64` relocations were found in the candidate extensions.

Pinned `maturin==1.15.0` (download SHA-256
`653020a63525bb224e5ab0adf02e17a2e08bc86dbea7fc1399c9a56d7529b99e`)
built a `musllinux_1_2_x86_64` wheel with `--release --offline --locked
--compatibility musllinux_1_2 --interpreter python3.12`. The final wheel
`peerwork_sdk-0.0.1-cp311-abi3-musllinux_1_2_x86_64.whl` has SHA-256
`e0e24a6e2b4a430af2fb58e00f441f80b867f21ba2ae38f0c264e0e6f3a4b990`.
Maturin copied hashed libc++, ABI, and unwind DSOs into `peerwork_sdk.libs`,
rewrote the extension's needed names and `$ORIGIN/../peerwork_sdk.libs` RPATH,
and included both the SDK and LLVM licenses. `pip install --no-deps --target`
into a fresh directory followed by import outside the SDK source tree passed
without a preload. The Node platform script in `28f9dd7`/`da3f3a7` copied
those three Alpine LLVM runtime DSOs into the musl platform package, set
relative `$ORIGIN/lib` and per-library `$ORIGIN` RUNPATH, and included the
LLVM notice. Its final tarball
`peerwork-agent-sdk-linux-x64-musl-0.0.1.tgz` has SHA-256
`3d6fa0cc585c887cc644772c4b89e0f1ac5504536aa3eb78627bfc3f30e310d4`.
An offline npm install into a fresh consumer loaded the addon; `ldd` resolved
all three C++ libraries from that installed package, not `/usr/lib`.

For actual service behavior, the test-only bridge source was exactly
`21aa303:tests/reference-kernel-server.mjs` (SHA-256
`bd7c42a3cc5194d51fddc3bef820419331089fd2d3946c28e50594426cd4f691`)
and its guarded tracked TypeScript service checkout was
`f828b6c50a0a58d1e718af90f653b214adcc3328`. The bridge created a fresh
synthetic PUBLIC workspace. The installed wheel imported the fixture's PKCS#8
owner identity, then authenticated and read sequence 1, 13 objects, and one
operation through the real service. The installed Node facade and musl binary
package independently returned the same verified checkpoint and counts. Both
returned redacted DTOs without raw JWS/keyring material. This is a scripted
business-path test, not an Agent workflow test: no Agent entry-instruction or
space-protocol compliance trace was collected, so workflow compliance remains
unverified. The bridge was intentionally stopped after the test (session
`34503`, exit 130); no test server remains running.

The first attempts remain distinct evidence: the minirootfs lacked DNS; Alpine
Rust was 1.87; Rustup's proxy needed `/proc/self/exe` but direct verified
Rust 1.89 binaries worked; a dynamic libstdc++ extension failed late-load
initial-exec TLS; a static libstdc++ candidate still failed late-load TLS;
the first libc++ configuration had an invalid global linker flag; missing
`llvm-libunwind-dev` caused `-lunwind` link failure; and a regular-file
`/dev/null` invalidated probes until the narrow bind. The first maturin
invocation lacked Cargo on `PATH`, the next lacked `patchelf`, and a second
repair initially saw maturin's already-patched intermediate copy before the
unmodified extension was regenerated. Two Node `-e` probes failed shell
quoting, then file-based probes passed. The first repeated Node packaging
failed on an existing `lib/` directory, corrected by idempotent directory
creation. None of these failures is counted as an Agent workflow deviation.

This checkpoint establishes one native x86_64 musl build and installed
Python/Node PUBLIC read. It does not establish musl arm64, older musl baseline
compatibility beyond the built `musllinux_1_2` tag, full secure ACTION/replay
parity, macOS or Windows execution, or release qualification. A final
standalone static CLI from the committed libc++ configuration and broader
installed APIs remain separate checks.

### Standalone musl CLI and matrix wiring

A first no-`RUSTFLAGS` CLI build from `0d714ae` completed but still had
`DT_NEEDED` entries for `libc++.so.1` and `libc++abi.so.1`; its successful
host `version` command was not counted as standalone compatibility. The first
explicit static-C++ selector then failed to find Alpine's installed
`libc++.a` until `build.rs` added a checked native archive search path.
The correction is committed as `7785a2e` (`build.rs` SHA-256
`b52d5ac867b761ebf99f7996bf9c502e86e3769fd047e9cfe026c415f58a6348`). With official Alpine
`libc++-static` and `llvm-libunwind-static`, the command
`PEERWORK_MUSL_STATIC_CXX=1 PEERWORK_MUSL_CXX_LIB_DIR=/usr/lib
cargo build --release --offline --locked -p peerwork-cli` completed in the
native rootfs. The resulting x86_64 musl CLI SHA-256 is
`e52661dfdc4b94adc631623bf82fed694d4cf87de1987849dcad3e76eecd942d`.
`file` identified a static PIE, `readelf -d` found no `DT_NEEDED`, and
`readelf -l` found no interpreter. It ran `peerwork version` on the GNU host.
Using a second fresh tracked-service fixture, the same host-run static CLI
imported the protected fixture PKCS#8 identity and returned the authenticated
PUBLIC sequence-1 checkpoint with 13 objects and one operation. The first
CLI test used relative protected-state paths and returned `IDENTITY_STATE`;
absolute paths corrected that test harness error. The fixture service was
intentionally stopped afterward (session `30008`, exit 130).

The experimental distribution workflow now includes a native Alpine x64 musl
job. It verifies the official minirootfs and Rust installer SHA-256 hashes,
imports that rootfs into Docker on an Ubuntu runner, builds shared extensions
with dynamic libc++ and a separate CLI with
`PEERWORK_MUSL_STATIC_CXX=1`, installs wheel/npm artifacts, runs the pinned
collation vector, and checks that the CLI has no dynamic dependencies and can
run on the GNU host. This CI job is source-only here: no GitHub runner log or
uploaded release artifact exists yet. The local namespace run above is the
observed native-musl evidence; macOS, Windows, musl arm64, older glibc floor,
and broader real-service installed functionality remain required release
checks.

### Musl CI notice-path correction (`8dbe11c`)

Independent source review found that the LLVM notice copy in `da3f3a7`
resolved its path from process cwd. The local package run started in
`bindings/node` and included the notice, but the CI step in `48277a4`
starts at the repository root and would fail before producing a tarball.
`8dbe11c` resolves both the LLVM and SDK license paths relative to the
packaging script URL and retains both tested npm tarballs as CI artifacts.
The corrected native Alpine packaging command passed from the SDK root and
from `bindings/node`; the root-cwd output loaded as a Node addon and its LLVM
notice SHA-256 remained
`8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee`.
The first root-cwd `node -e` probe failed JavaScript shell quoting, then an
equivalent file-based import passed. This source correction was not exercised
by a GitHub runner and did not change the earlier installed wheel or tarball
binary evidence.

### Native manylinux 2.28 installed interface checkpoint (2026-10-13)

The official `quay.io/pypa/manylinux_2_28_x86_64` image was selected by its
Docker v2 manifest SHA-256
`4131ddd7acb9c6c966af02fe7e71edc51e078c2d41f475966697676430bfa2ae`
(23 layer descriptors, 21 unique blobs, about 0.56 GiB compressed). Every
config and layer blob was checked against the manifest's size and SHA-256.
The Docker media-type descriptors were converted to OCI descriptors only
(converted manifest SHA-256
`bfaf98c6a5140fde2a56b13b846f5e236514525df2781f3e77d3289b566046c8`);
the verified layer and config bytes were unchanged. Task-local `umoci`
0.4.7+ds-4+b10 was extracted from the Debian package with SHA-256
`d6c837c39304a646e3cd3ee1ec329a5ab936bbe1e22538edc950b72e32eca9cc`
and unpacked the rootfs. A native user namespace and `chroot` reported glibc
2.28 and Python 3.11.17. The image's default `gcc` is 8.5.0, while SDK
build commands selected the image's GCC Toolset 14 using `/opt/rh/gcc-toolset-14/root/usr/bin`
in `PATH`. The official Node 24.20.0 GNU tarball SHA-256 was
`2f2c0da162318f0de47665410c7c8c2ed3d36c8f3105de4bbc61176c70a7cbf2`;
its highest required glibc symbol is 2.28 and it ran inside this rootfs.

The build used immutable `git archive
7831650565ee4056e7b54c2f59d64b7e1154a4e7` under `/work/sdk` plus only
the byte-identical, separately committed GNU ICU PIC correction `6596631`
(`crates/core/build.rs` SHA-256
`813fe2032bc0fc33b87f9c0b5e9fbbdf6fe2ce8e854f570bde8c671196dec303`).
The vendored ICU source archive still matched its pinned SHA-256
`3a2e7a47604ba702f345878308e6fefeca612ee895cf4a5f222e7955fabfe0c0`.
Official Rust 1.89.0 GNU archives were checked against their published
SHA-256 sidecars: `rustc` `b42c254e1349df86bd40bc28fdf386172a1a46f2eeabe3c7a08a75cf1fb60e27`,
`cargo` `99fc10be2aeedf2c23a484f217bfa76458494495a0eee33e280d3616bb08282d`,
and `rust-std` `2719470dcd78b3f97d78b978c8f85a1a58d84ff11b62558294621c01bca34d49`.
The official Rustup GNU installer was SHA-checked too
(`dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71`),
but could not start because this user namespace denied mounting `/proc` and
Rustup requires `/proc/self/exe`. The verified component archives were
installed directly under `/opt/rust`. Its `rustc` needed
`LD_LIBRARY_PATH=/opt/rust/lib` in the **build** environment; no installed
Python, Node, or CLI consumer process used that variable.

The first native core test failed at the GNU linker: ICU's static `ucol.ao`
contained a non-PIC `R_X86_64_32` relocation, invalid in the Rust PIE.
Task-local `CFLAGS=-fPIC CXXFLAGS=-fPIC` made the pinned Node/ICU collation
test pass 1/1. Commit `6596631` appends `-fPIC` to inherited C and C++ flags
for GNU Linux ICU configure and make only, tracking both environment inputs;
it leaves the musl and Windows selections unchanged. The affected native
core test passed 1/1 again with **no external PIC flag override**. This is
the tested source correction, not an untested environment workaround.

Pinned `maturin==1.15.0` was installed offline from the previously verified
static wheel (SHA-256
`653020a63525bb224e5ab0adf02e17a2e08bc86dbea7fc1399c9a56d7529b99e`).
Its native manylinux build produced
`peerwork_sdk-0.0.1-cp311-abi3-manylinux_2_28_x86_64.whl` SHA-256
`e1aa24249faa8ce7fd4cfde56858e6f04336aaa4d270b173f10a7b780668d0db`.
An offline install into a fresh Python target loaded `peerwork` from that
target. The extension's highest required versions were `GLIBC_2.28`,
`GLIBCXX_3.4.11`, and `CXXABI_1.3.8`; its dependencies included baseline
`libstdc++`, `libgcc_s`, and glibc, with no bundled C++ DSO. The native
Node addon and CLI release build passed. Packed offline npm tarballs were
the facade SHA-256
`5411f265ebb19ba5a24e8551102dc0f79e6c9a774d78da9bba134508dc51ad0d`
and GNU platform SHA-256
`d5247b71f730c62e754c8ae976786f411472764801ac6f57175ead53a394f8b7`.
Their clean offline install loaded the addon on Node 24.20 without the
toolchain library path. The CLI SHA-256 was
`99e67f8da2b9beeb4b60f61a70acf1cbb78d314fddde2ef44598a9d69dbf1fa7`;
its highest required glibc symbol was 2.28, and `version` ran in the same
rootfs without a build environment. The first Node archive extraction tried
to restore archived uid 1000 and emitted ownership errors in the namespace;
`tar --no-same-owner` corrected extraction. The first npm consumer probe
also wrote malformed `package.json` through shell quoting; writing the exact
JSON file corrected that test fixture.

An opt-in, fresh synthetic actual-service test used
`7831650:tests/reference-kernel-server.mjs` (SHA-256
`cd85cbf1a7a31b954609690bc4ef4cb8245112ff66beca28eb5509812879b637`)
and its guarded TypeScript reference checkout
`f828b6c50a0a58d1e718af90f653b214adcc3328`. The tracked service
fixture ran on the host with pinned Node 24.20; **all installed SDK
consumers ran natively inside the glibc 2.28 rootfs** without
`LD_LIBRARY_PATH`. The task-local orchestration SHA-256 was
`51d6d6c1e065f4ba7b4b38e8f7c68ffe38cb690ed533bc29b324e20e6136b804`.
It observed a PUBLIC bootstrap at sequence 1, Python's verified read and
native ACTION submit with a lost HTTP reply (`PENDING`) at sequence 2, Node's
verified read and exact command reconciliation (`ACCEPTED`, one effect),
CLI's exact retry (`ACCEPTED`, no extra commit), and Python's final verified
record readback. Service commit counts were 1 → 2 → 2. The five synthetic
stage offsets from fixture start were 1,320, 3,465, 6,680, 8,285, and
10,879 ms; they are not user acquisition or general install timings. The
owned service was intentionally terminated after the run (exit `-15`). This
establishes the specified installed business path on glibc 2.28; it does
not establish Agent instruction-following. No Agent tool-call trace was
collected, so workflow compliance remains **unverified**.

This local native run does not establish a GitHub workflow run, macOS/Windows
execution, ARM64, every supported signed history, or a release candidate.
The experimental distribution workflow now has a separate GNU x64 job using
the official OCI manifest digest above, pinned Rust 1.89 and Node 24.20
inputs, the ICU vector, offline installed wheel/npm imports, CLI execution,
and an ELF `GLIBC_2.28` ceiling check. Its shell block passed `bash -n`
after extraction from the workflow. That job has **not** run on GitHub;
the guarded reference checkout is unavailable there, so the job does not
claim the actual-service action test above.
