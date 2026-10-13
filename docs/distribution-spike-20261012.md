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

### ARM64 emulation feasibility, 2026-10-13

This is a **QEMU-emulated** aarch64 runtime and Rust compiler probe on an
x86-64 host, not native ARM hardware, an SDK build, a linked executable, or
an installed SDK acceptance test. No global binfmt registration, host kernel
change, or operator-state mount was used. All inputs and outputs are under
ignored task-local `.build-artifacts/arm64`.

The Debian repository's `qemu-user` 10.0.13+ds-0+deb13u1 amd64 package was
downloaded without installation; its SHA-256
`ca6ede739327a20ae5a3498230c8a3a9a072c586e131bc6bcc1201eb1725e336`
matched `apt-cache show` repository metadata. The extracted static-pie
`qemu-aarch64` SHA-256 is
`73cc2584f119f9e74c85c0a8549dbb6fd104ae3897a06a7500797f9e5b4d0943`.
The official Alpine 3.22.6 aarch64 minirootfs archive SHA-256
`821565fa8f3953eefd12497b166b4b50add2f7c57fb312e75862f5867e06fefe`
matched its published `.sha256` sidecar. The first local sidecar command
failed because it ran from the SDK root instead of the download directory;
running `sha256sum -c` inside that directory passed. Running the extracted
BusyBox via `qemu-aarch64 -L <rootfs> <rootfs>/bin/busybox uname -m` exited
0 and printed `aarch64`.

The official Rust 1.89.0 aarch64-musl `rustc` archive SHA-256
`9f463709166a6cce04d218160a6d85a5ce262b00e0a69101509a518a16f9102e`
and matching `rust-std` SHA-256
`611633874e2000fd84807be65d82a6dfb7735c728969f5c8f62cad66702e6681`
both matched their published Rust `.sha256` sidecars. The first `rustc
--version` attempt failed at guest loading because the minimal rootfs lacks
`libgcc_s.so.1`. The official Alpine v3.22 main/aarch64 index (downloaded
archive SHA-256
`90cb1d2d05e01cb5467946403a6e240e5a2899ad80c0a6167f35b1bac40901cf`)
identified `libgcc` 14.2.0-r6. Its downloaded `.apk` SHA-256 was
`ba1835eec3ad8a120efd3d5020e561d53553a0513763a08f509e3ce6d4baa9ca`;
Alpine `apk verify` reported `OK`. After extracting only its guest library,
`qemu-aarch64 -L <rootfs> <rustc>/bin/rustc --version` exited 0 and printed
`rustc 1.89.0 (29483883e 2025-08-04)`. A first tiny compile failed with
`E0463` because `rust-std` is a separate component. Adding the verified
standard library and rerunning `rustc --emit=llvm-ir hello.rs -o hello.ll`
exited 0, emitting 7,822 bytes of LLVM IR with target triple
`aarch64-unknown-linux-musl` (output SHA-256
`c556a4ac4c680a2f143c06748e53ccfd51cb1c7822b868cbac834c948757dfab`).
This validates guest loader and compiler execution only. Guest subprocess
translation, linking, executing an ARM64 binary, SDK build, and dependency
closure remain to be tested.

The next bounded link probe used Debian repository-pinned `proot`
5.1.0-1.3+b1 (SHA-256
`7ca9260edf1ca6666f9b33e1da551638055934d673117acd135ff5367f420744`)
and `libtalloc2` (SHA-256
`b4cc8aa74c8b7c05a64efb6577acc955f522a8e39d8f37fe60b1b3fe6634ce96`)
without host installation. Task-local `proot -q qemu-aarch64` failed with
`ptrace(TRACEME): Operation not permitted` both in the default sandbox and
the permitted unsandboxed retry. A user-namespace retry got beyond that
error but failed to discover its loader through `/proc/self/fd`; that
namespace has no mounted proc. No host binfmt or proc mount was added.

Direct QEMU orchestration does link and execute a tiny ARM64 program without
proot. A first emulated `rust-lld` invocation received GCC-driver `-Wl`
arguments because rustc's default linker flavor was wrong for raw lld. An
experimental task-local argument-translating wrapper linked it, but the
final probe used stable `-C linker-flavor=ld.lld` and a simple wrapper that
only invokes the verified guest `rust-lld` through QEMU. The first such
wrapper mistakenly supplied `-flavor gnu` twice; removing that duplicate
fixed the probe. `rustc hello.rs -C linker-flavor=ld.lld
-C linker=<qemu-rust-lld-wrapper>` exited 0; `file` reported a statically
linked aarch64 executable, and direct QEMU execution printed
`arm64 toolchain probe`. The 4,229,928-byte executable SHA-256 is
`cd8b43c9116f36a95947e16dfe78f794cfc30ec212ead75a686110763612c6c0`;
the final task-local wrapper SHA-256 is
`1d1ab7cc05d744ea209ec76f880bf7d6203e6d63730051f0bda5a996ba7926dd`.
This is a linked guest Rust hello, not an SDK build or package test.

The next SDK build is materially larger: the current core ICU build script
refuses host/target cross builds, while a full guest Cargo build needs
translated child processes and a guest C/C++ toolchain. The successful
single-process QEMU/rust-lld probe does not establish either. A first ARM64
SDK build would require a target-native guest execution route with working
`/proc` and child translation, or a separately engineered cross build that
preserves pinned ICU data/source, target C/C++ archives and linkage. It would
then need ARM64 Python/Node extension packaging, dependency closure, and
emulated installed API tests. No duration or package size is claimed from
this tiny probe; the work spans toolchain, ICU, two extensions, CLI and
installed-service validation rather than a single rerun of x64 jobs.

### ARM64 ICU cross-build follow-up, 2026-10-13

The task-local cross-toolchain now built the **pinned ICU4C 78.3 ARM64 static
archives** and executed an ICU collation consumer under direct QEMU. This is
cross compilation plus emulation on x86-64, **not** native ARM hardware and
not yet an SDK wheel/addon/CLI build. All new inputs/output are under ignored
`.build-artifacts/arm64`; build temporaries used workspace-owned `TMPDIR`.
The ICU source archive SHA-256 remained the code-pinned
`3a2e7a47604ba702f345878308e6fefeca612ee895cf4a5f222e7955fabfe0c0`,
and filtered data SHA-256 remained
`790a1d07c4a9e4d7de4eab025cc97b54e0097de2ad94408d190ea55c37fcd7e5`.

Alpine x64 Clang 20.1.8 from the earlier verified native rootfs was copied
and patched only in task storage with that rootfs's musl interpreter and
relative-library search path; copy SHA-256 is
`f66ab1ab13459df8bd0e800f15020ce64548369d63eec36fc455e8a062dd64ed`.
This lets Clang run its own `-cc1` child without host binfmt. The ARM sysroot
starts from the previously verified official Alpine 3.22.6 aarch64 rootfs and
repository index. The downloaded target `.apk` files passed Alpine's `apk
verify` without host installation: `musl-dev` SHA-256
`576f4aabcfa01d10d6baa2d5d87de436b76e58ae76eedf9db7627051365e1fe3`,
`gcc` startup objects
`0224b985a055ef90324dee9a65c5683f28499f0798db23cae90b40ebba620772`,
`compiler-rt`
`9dd65d86b36b824202b4d5e6eec3da7b922f74adee585a6824c659669c8a6875`,
`libc++` `4afc81da0a024a27bee4a703fd5a8c16bd7f2c5d869b1243a33930715bfe0194`,
`libc++-dev`
`cc8122215fd85ddc1a700fd0e93359c37763a5375efbe6f5c31b13bddc8602a4`,
`llvm-libunwind`
`9604c7b55ed77b8d243801fb9d39e74617671f5cf1f7e2018fd98482f6929f81`,
and `llvm-libunwind-dev`
`d5b584b1b281883a418d529818799923249d7f6f4b4855353d63c57e7d57345a`.
The signed packages were extracted into a separate scratch sysroot; no system
package database or operator state changed. Wrapper SHA-256 values are
`91d6d839bd3391e7fcd1a39ab478c41b22f99263b541435ed4691ab4d218fe66`
(C) and `474fcd49f097dabb4208520bbd750a2794a4add1f95bd819cc25faf5ba1208c1`
(C++). They select `--target=aarch64-alpine-linux-musl`, the scratch sysroot,
Clang's pinned resource directory, and the existing QEMU guest `rust-lld`
wrapper.

The first package-manager simulation could not open uncached online indexes;
the package names/versions were instead read from the previously downloaded
official index, fetched by exact URL, and signature-verified. The first C++
link missed `crtbeginS.o`/`libgcc`, then linked against the wrong GNU
`libunwind` and failed under QEMU because Alpine `libc++` needs LLVM
`libunwind.so.1`. A clean LLVM-libunwind sysroot corrected that. Calling the
unpatched Clang through the musl loader also failed when it tried to spawn
`-cc1`; the task-local ELF interpreter patch corrected self-execution. The
first combined compile/link invocation used `--resource-dir`, which Clang
rejected; its supported `-resource-dir` option passed. A C++ string binary
then compiled, linked, and ran under direct QEMU with exit 0.

ICU was configured out of source with `runConfigureICU Linux
--host=aarch64-alpine-linux-musl --enable-static --disable-shared
--with-data-packaging=archive --with-library-suffix=peerwork
--with-cross-build=<existing pinned x64 ICU host-tool build>`, `CC`/`CXX`
set to those wrappers, and `CFLAGS`/`CXXFLAGS=-fPIC`. This follows the
[ICU project's cross-build procedure](https://unicode-org.github.io/icu/userguide/icu4c/build.html).
Configure exited 0 and identified build=x86_64, host=aarch64;
`make -j4` exited 0 in session `84613`. Compile-only stages emitted benign
unused-linker-option warnings. `ar p | file -` identified ARM aarch64 ELF
members in the output archives: `libicui18npeerwork.a` SHA-256
`6b43112393b706ce449ff4e914584c53a2540026daabda565c9736f45a97f542`
(10 MiB), `libicuucpeerwork.a`
`c2251f42db2b29364c174ff022f1a98cf19896b9cf1116da78cbaf74d88856bc`
(4.9 MiB), and `libicudatapeerwork.a`
`efc4214727f60092aedd1e0b8ae2d752ed33ef7596b30d4447619770f3f33d8f`.
An actual ARM64 program linked against these three archives, loaded the same
pinned filtered `.dat` through `udata_setCommonData`, and used `ucol_strcoll`
for `a-1` versus `a_1`. Direct QEMU exit was 0 and comparison result `1`,
matching pinned Node 24 `Math.sign('a-1'.localeCompare('a_1','en-US')) == 1`.
The consumer binary SHA-256 is
`a031cd1d604617720c460299abf4ed9e013a157ecb36bfdb1cf9cc985a318607`;
`readelf` reports ARM64 musl plus `libc++`, `libc++abi`, and LLVM
`libunwind` runtime dependencies. This one-pair smoke establishes actual
ICU link/load/use under emulation, not the full pinned collation vector suite.

The next step was a reproducible opt-in core build-script cross branch that
rebuilds host tools and target ICU from the verified archive, then a consumed
ARM64 SDK artifact. That continuation is recorded below. ARM64 package
dependency closure, installer wiring, real ARM hardware and macOS/Windows
execution remain open.

### ARM64 SDK CLI consumed under QEMU, 2026-10-13

SDK `crates/core/build.rs` commit `dbda343` (file SHA-256
`75ad09695c5c8ba8a05bc4a453669bdcd78f67bfba82852500fb6c077f8f164b`)
adds an opt-in `HOST!=TARGET` branch only for
`aarch64-unknown-linux-musl`. It still verifies the pinned ICU archive and
filtered data SHA before extraction, builds native host tools from that
archive, then uses `PEERWORK_ICU_ARM64_CC/CXX` absolute task-owned wrapper
paths for a static ARM ICU build with `--with-cross-build=<host-build>`.
The existing native Linux build path passed Rust 1.89 offline locked
`cargo check -p peerwork-core` on the shared source. A target check with the
verified Rust 1.89 ARM standard-library archive SHA-256
`611633874e2000fd84807be65d82a6dfb7735c728969f5c8f62cad66702e6681`,
task-local sysroot, target linker wrappers, `--offline --locked`, and
`--target aarch64-unknown-linux-musl` completed in session `70944`, exit 0
after 5m25s. This was a compilation check, not an executable run.

The first full `cargo build -p peerwork-cli --target
aarch64-unknown-linux-musl --offline --locked` in session `25618` exited
101: `libsqlite3-sys` could not find its default
`aarch64-linux-musl-gcc`. That failure is separate from the successful ICU
cross-build. Supplying `CC_aarch64_unknown_linux_musl` and
`CXX_aarch64_unknown_linux_musl` as the verified task-local Clang wrappers,
with task-local CMake 4.4.4 already present in the earlier manylinux bundle,
made the corrected build pass in session `69728` (27.74s). The final build
used `-C target-feature=-crt-static` for a dynamically linked executable
and `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER` set to the ARM Clang++
wrapper. It used the same Rust 1.89 host compiler, task-local ARM standard
library, pinned ICU source/data, offline Cargo lock and workspace `TMPDIR`.
The source HEAD for the successful consumed build was
`08f0963a1fac7932829423a9f76944d192cce163`, including the committed
build-script branch; unrelated admission source changed between the first
failed and corrected runs, so the failed run is a toolchain diagnostic rather
than an exact-source product regression.

The resulting task-local debug `peerwork` CLI SHA-256 is
`c5e2408f2f81823079a5454d1d435f4c68ddffc72bc040df1eb441f8a7986128`.
`file` identifies a PIE ARM aarch64 ELF using `/lib/ld-musl-aarch64.so.1`;
`readelf -d` lists `libc++.so.1`, `libc++abi.so.1`, `libunwind.so.1`, and
`libc.musl-aarch64.so.1`. Direct task-local QEMU with the verified ARM
sysroot and `/usr/lib` guest search path ran `peerwork version` and
`peerwork capabilities`, both exit 0, returning experimental version 0.0.1
and the expected redacted capability flags. The first `--version` call
returned usage exit 1 because the CLI accepts the `version` subcommand;
no SDK failure was hidden by that corrected invocation.

For an actual consumed ICU check, a task-local QEMU Cargo runner SHA-256
`c79f2cc8d42fc5fad5c5b38199e3a06ff9bd4e0c69dc6b5e049b3b3f85022c25`
ran the ARM64 `peerwork-core` test binary. The first filter with `--exact`
selected **zero** tests; the corrected
`pinned_node_locale_compare_vectors` filter ran
`js_locale::tests::pinned_node_locale_compare_vectors` and passed 1/1 under
QEMU, exercising the SDK's pinned ICU collation path. This is cross-built
SDK CLI code and a core test executed by **emulation**, not a native ARM
machine, release package, installed HTTP workflow, Python/Node extension,
or dependency-closed distribution artifact. Those acceptance gates remain
open, along with actual Windows and macOS runs.

### ARM64 CLI signed HTTP action/recovery, 2026-10-13

The same **unchanged** 08f-source ARM CLI SHA-256
`c5e2408f2f81823079a5454d1d435f4c68ddffc72bc040df1eb441f8a7986128`
was run through direct QEMU against a fresh local HTTP fixture. The exact
service implementation remained tracked commit
`f828b6c50a0a58d1e718af90f653b214adcc3328`; the archived SDK fixture
from source `08f0963a1fac7932829423a9f76944d192cce163` had SHA-256
`ed67bc57e2b37eafd0c31bba72d6f9ecb23cce6d07427549008642eb160d2592`.
The task-local orchestration script SHA-256 was
`f12d04d714af40ccb19fbc8d730de79d578f7d4f1eca4074b2fe40e3fb989067`;
it pins both inputs and creates only a fresh mode-0700 workspace state dir.
The tracked TypeScript fixture creates the initial PUBLIC workspace and
supplies the owner PEM/pins; Rust CLI imports that protected PEM, fetches and
verifies signed sequence 1, authors `discussion.post`, and submits the exact
saved request. The fixture applies the first POST and drops its reply.
Independent QEMU CLI processes then list the pending command locally,
reconcile from signed journal sequence 2, retry the same saved ID, and read
the verified added record. Counts were commits `1 → 2 → 2`; one effect
record, matching command ID, and identical accepted reconciliation/retry
receipts were asserted. Local-socket session `53048` exited 0. This is
scripted business/recovery correctness; it does not test independent Agent
instruction-following compliance.

Before that service run, a small identity probe first used a relative path
under a mode-0755 parent and correctly returned `IDENTITY_STATE`; an
absolute path under a task-owned mode-0700 parent let ARM CLI `identity
create`/`identity info` match. No protection rule was changed. The service
test used the latter protected path pattern. Its host Node fixture and
control/count queries ran on x86-64; all SDK CLI commands ran as ARM64 under
QEMU. Dynamic libc++/libc++abi/LLVM-libunwind dependencies came from the
task sysroot, so the run is **not** a dependency-closed installed ARM
package or native ARM hardware result. Python/Node ARM extensions and an
installed ARM package remain open.

Reviewer inspection of `dbda343` found the initial cross branch accepted
arbitrary `HOST` values while invoking Linux `runConfigureICU`/`make`. A
scoped follow-up `768f367` (build.rs SHA-256
`23c93655531440025113caf86663d6d9d4f2e99f0d3e6e0d28433c5817e32356`)
now requires the tested `x86_64-unknown-linux-gnu` host only when
`HOST!=TARGET`, preserving native macOS/Windows paths. Rust 1.89 offline
locked native `cargo check -p peerwork-core` exited 0. A standalone
compilation of that exact build script and simulated
`HOST=x86_64-apple-darwin`, `TARGET=aarch64-unknown-linux-musl` exited 101
before extraction with the explicit host contract message. The first
standalone compilation selected an unrelated cached sha2 ABI and failed
`LowerHex`; selecting the build script's matching sha2 artifact corrected
the probe. No ARM CLI artifact was rebuilt for this host-only guard, and
the 08f service result is attributed to its original binary and fixture.
