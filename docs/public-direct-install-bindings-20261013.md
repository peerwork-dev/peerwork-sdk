# PUBLIC direct-install binding checkpoint, 2026-10-13

Python `SecurePublicPackageInstaller`, Node `openSecurePublicPackageInstaller`,
and CLI `secure install-begin|install-continue|install-pending` were committed
as `996dab4d3847dce93554ed940f094626437f79f4`. They accept an explicit
local package closure and expected package/protocol digests, expose redacted
BEGIN/progress/pending results, and use the runtime's protected exact packet
and signed replay. A digest/compiler match does not authenticate a remote
publisher. Local pending discovery does not establish service acceptance.
The runtime generic continuation and local-only pending-list seam is
`fe579fe`. A source trace found that its earlier borrowed replay would open
network discovery; the corrected stopped-service test passed. The first
observed offline `Read(Discovery)` failure belonged to the separate ACTION
pending-list path, not this install regression. The
runtime's later `64a195e` interim guard refuses nonempty BEGIN before save or
POST; it is absent from the immutable binding artifacts below. PAGE/END for
nonempty snapshots remained open at this checkpoint.

Rust 1.89 `cargo check --offline --locked` passed for runtime, CLI, Python
native and Node native against `fe579fe` plus the wrapper source. Python
`py_compile`, pinned Node 24.20 syntax, rustfmt and `git diff --check`
passed. A strict TypeScript 7.0.2 consumer of the Node declaration passed
after the first invocation's TS5112 required `--ignoreConfig`.

An exact detached worktree at `996dab4` with `Cargo.lock` SHA-256
`9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`
was built using Rust 1.89 offline locked, maturin 1.15.0, Python 3.11.15
and Node 24.20.0. Release CLI/Node build and wheel build exited 0. Wheel
SHA-256 is `50b38eee4c3db21a4aea575f78fcac77485e6be63720fe1053e729e2a66a9f40`;
offline npm facade and GNU platform tarballs are
`40d9d3a9b360af7717d8e6c44cd32e5fb4f30593ac18c592a39865d612001f7e`
and `ec3f9e730db5898925725aafe550276be5c9694b439617e78e2c33e75508760c`.
The CLI is `9e35c3d8454b967946a616a3c09ac84f7afed91c7498e1b173e18692a98d3795`;
the packed Node addon is
`def1ab115a368fc2650d789e316bc72261a4c8bc876a3426d97a07e404232409`.
Fresh offline pip and npm consumers imported their installed package paths.
The first npm pack attempt failed because `npm` could not locate `node` on
PATH; adding the pinned Node bin directory passed without source changes.

The opt-in installed test used the guarded tracked TypeScript service at
`f828b6c50a0a58d1e718af90f653b214adcc3328`, synthetic PUBLIC owner
fixture, and proposal/adoption closure. The source test initially failed
before fixture startup under the sandbox's `spawnSync git` EPERM. Its
authorized localhost run then passed: Python BEGIN saved a generated ID
before a fixture 503; after the service stopped, the Python client and fresh
Node and CLI processes all listed the same redacted pending row. In a second fresh workspace, Node
BEGIN's first response was dropped yet returned PENDING, Node/CLI continuation
reached signed ACCEPTED at sequence 3, and verified readback reported ACTIVE
without another commit. A third fresh workspace exercised CLI BEGIN. This
first source test at `996dab4` did not reach Python continuation because the
install completed in two steps. Test-only `70d84da` added idempotent Python
continuation **before** verified readback, and that run passed against the
same installed artifacts.

The stronger test-only `b6737b7` (file SHA-256
`4787bf57a1d585d800a13c090f1f9b01b369f87a5a4a03e1edc59a294a15ad6e`)
placed Python continuation **after** verified readback had advanced the
protected profile to ACTIVE sequence 3. The unchanged `996dab4` installed
runtime then refused with `selected package, grants, or install context is
invalid`. The runtime rechecked the saved BEGIN against the now-current
checkpoint rather than its original source checkpoint. This is an open
idempotency defect at this artifact pin; the earlier passing test proves
only the narrower pre-readback behavior. No general nonempty-install or
complete public installation capability is claimed. These are business-path
tests, not Agent usability tests. No Agent instruction or tool-call trace was
collected, so workflow compliance is **unverified**.
