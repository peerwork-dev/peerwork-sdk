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

The manifest is experimental: version and capability introspection are the
only public entrypoint operations. Its other capability flags describe core
primitives and do not establish a completed Agent workflow.

The initial native kernel intent journal checks Unix ownership and file modes.
It deliberately refuses to open protected state on Windows until ACL handling
and the separate secure-agent state path are implemented and exercised there.
Windows package loading in the distribution workflow therefore cannot be
interpreted as Windows action/recovery support.
