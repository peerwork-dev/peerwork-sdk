# Native distribution spike, 2026-10-12

This checkpoint validates packaging only for version/capability introspection.
It is not a functional SDK acceptance result. The core's cryptographic and
wire primitives are in progress, while verified reads, actions, and durable
recovery are marked false in the manifest.

## Local Linux x86_64 observation

| Check | Command or observation | Result |
| --- | --- | --- |
| Rust workspace | `cargo test --workspace` after dependency fetch | Exit 0 for initial scaffold; subsequent core edits require fresh tests |
| CLI | `cargo build --release --offline --locked -p peerwork-cli`; `env -i PATH=/tmp /absolute/path/peerwork version` | Exit 0, `0.0.1`; 502 KiB binary at checkpoint |
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
