# Platform support evidence

No public platform claim is frozen. The intended matrix includes Linux glibc
and musl on x86_64/arm64, macOS x86_64/arm64, and Windows x86_64. Windows arm64
is deferred until a real runner and the complete binding matrix pass. Browser,
mobile, WebAssembly, edge isolates, and 32-bit systems are outside this release
target.

The `distribution-spike` GitHub Actions workflow builds and executes the CLI,
Python wheel, and Node addon on representative Linux, macOS, and Windows
runners. Its current glibc Linux x64/arm64 and macOS arm64/x64 labels follow
[GitHub's hosted-runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).
A workflow file alone provides no execution evidence. Target support
will be recorded here only after successful real runner logs, downloaded
artifacts, binary dependency inspection, and offline/no-compiler consumption
tests. Cross-compilation or emulation, where used, will be labeled explicitly.

The manifest is experimental. Public identity, read, action, admission and
package operations now exist, but their capability flags do not establish a
completed Agent workflow or platform support by themselves.

Protected local state has source branches for Unix ownership/modes and Windows
current-user ACLs. On Windows, the runtime rejects reparse/hard-link paths and
broad directory/file DACLs, holds an OS file lock, atomically replaces state,
and checks SQLite journal sidecars. The workflow's Windows `cargo test
--workspace --locked` would exercise its platform-specific tests when the job
runs. The installed package smoke now configures a protected current-user
directory and checks identity create/reopen through Python, Node and the CLI,
including paths with spaces and non-ASCII characters. It uses public IDs only
and does not contact a service. Its Linux execution is recorded separately;
Windows and macOS job execution, encrypted action/recovery, cancellation and
dependency closure remain unverified until actual runner evidence exists.

The installed identity gate is pinned at `0fd464d4f984e9d936f92b0558b509cd22964fa7`.
On local Linux, its source-identical script ran against immutable `a0908ee`
installed artifacts: CLI SHA-256 `41b3f2626d1dce47b42ed24573a9053b5fffe360f393567c40524c59d81de26b`,
Node addon `5f49183f48491129e002dc77ad1f8140182d9fafffa01f6d2c94e5e1277e3e4b`,
and Python extension `5a848ab003c6615df760c83f035ec316035eeb6b5cf60206a1e7d0b63a1579c4`.
An existing 0700 task directory named `state Ω with spaces` was supplied as
the state root. The test created one fresh identity per interface, reopened
each through all three installed interfaces, compared only public actor/key
IDs, and exited 0. Each child process has a 30-second timeout. The first
attempt exited 1 before state creation because the harness resolved the venv
Python symlink to the host interpreter; retaining the venv pathname corrected
that harness error. This test is scripted installed API behavior, with no
service call or natural Agent workflow observation.

```sh
python3 tests/installed-protected-identity-smoke.py \
  --python "$PWD/.build-artifacts/private-stage-a090/install/venv/bin/python" \
  --node /root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node \
  --node-consumer "$PWD/.build-artifacts/private-stage-a090/install/node" \
  --cli "$PWD/.build-artifacts/private-stage-a090/build/target/release/peerwork" \
  --state-dir "$PWD/.build-artifacts/platform-identity-smoke/state Ω with spaces"
```

The workflow now prepares the caller-supplied protected root as fixture setup:
0700 under the canonical runner temp path on Unix, and a protected one-ACE
current-user DACL on Windows. The identity API itself still requires a private
parent; this fixture setup is not evidence that identity creation makes one.
Linux/macOS Bash blocks passed syntax checks, while the Windows PowerShell
block and all remote jobs await real runner execution. The bounded Windows
acceptance command is the existing `cargo test --workspace --locked` followed
by `tests/installed-protected-identity-smoke.py` in the Windows job; it must
show three creates and nine cross-entrypoint reopens under its protected root.
