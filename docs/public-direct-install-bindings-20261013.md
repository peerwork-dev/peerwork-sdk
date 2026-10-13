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

## Corrected installed candidate

Core checkpoint `d859deb` corrected repeated continuation after the ordinary
verified read advances the protected profile. The corrected candidate also
contains the `64a195e` nonempty-BEGIN pre-POST guard, so unsupported nonempty
snapshot input refuses before an install is staged. Separately,
`c9189fc7a05ea148ea0a66ebe3de402dcdea1d6e` added redacted
`PublicActionError` distinctions without changing uncertain-submit PENDING
semantics. Its focused Rust intent-code test passed 1/1; the installed action
test checks a duplicate command ID returns `INTENT_CONFLICT`, an unknown
saved ID returns `INTENT_NOT_FOUND`, and neither creates another service
commit. The existing action flow still completes three signed effects at
sequence 4.

An immutable detached checkout at exact `c9189fc` built CLI, Node addon and
Python wheel with Rust 1.89 offline locked, maturin 1.15.0, Python 3.11.15
and Node 24.20.0. Release CLI/Node and wheel builds exited 0. Clean offline
pip/npm consumers imported from installed package directories. The wheel
SHA-256 is `873b1850791fdac3f2994709ca9328022cc515d9782e39040e52cb676d6e0c9f`;
facade and GNU platform npm tarballs are
`40d9d3a9b360af7717d8e6c44cd32e5fb4f30593ac18c592a39865d612001f7e`
and `f06ecb0415f79182b1c68743b16c8ef7baf7139a3a1f94c84e00b80b7489d55e`;
CLI and packed Node addon are
`f99ac7dfb2ffb79dd12dfe6d3d34eb08072e8aad1984edcc909704936d023a63`
and `e81732188ef2424739cfdf7c9147c3060e975e30d312e5b47a7b1c9ab72b2f87`.
The Cargo lock hash remained
`9dc2d3f2ad77be15366633af890168611e8d62a7f38de646970dfc4cedc8d4d5`.

The exact `b6737b7` stronger installed test (SHA-256
`4787bf57a1d585d800a13c090f1f9b01b369f87a5a4a03e1edc59a294a15ad6e`)
exited 0 against `c9189fc` artifacts and the pinned f828b6c TypeScript
service. On fresh synthetic state, Python's rejected BEGIN still left a
generated protected pending ID; after server shutdown, Python, Node and CLI
listed that same row without any available service. In a second fresh
workspace, Node BEGIN applied after a dropped response and returned PENDING;
Node/CLI continuation reached signed ACCEPTED at sequence 3. Verified
readback advanced the profile to ACTIVE sequence 3, and a Python repeat of
the same BEGIN ID then returned ACCEPTED with the same commit hash and no
additional POST/commit. A third fresh workspace exercised CLI BEGIN. The
installed action smoke (SHA-256
`33226c3bbf2cabbf08d4295b2db5902d8602bc343f53645debd9e022159b85da`)
also exited 0, including the error-code assertions. The guarded service
bridge SHA-256 was
`f85c4416752ff31a62d1328749a00122b9e363822dcae1a7a17e9aa617399bfe`.

These results close the after-readback idempotency finding for this supported
zero-record PUBLIC install and the tested action error distinctions. They do
not establish nonempty PAGE/END, external package publisher authentication,
all platforms, or full Agent workflow compliance. The installed tests used
synthetic owner/service state; no Agent instruction/tool trace was collected,
so workflow compliance remains **unverified**.
