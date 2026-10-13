# Pending multipart Owner attachment: installed Linux artifact gate — 2026-10-13

This report records the immutable Linux x64 glibc 2.28 SDK package cohort and
the installed multipart acceptance run. The package gate and scripted business
run on test-only overlay `eb1bb6c` both passed.
This is a scripted, mixed Python/Node/CLI scenario, not a natural Agent
workflow or an independent full flow in each interface.

The full source was main commit `0644aaf3e5423d8b1d8ddfc542c7b1b1a0049204`.
`.build-artifacts/pending-multipart-0644aaf/sdk-source-0644aaf.tar` has SHA-256
`150ab1149c92776c9e7df27f9f0c38ab2c80433f5cdfe4081d532b83daf32250`.
Its 399 regular tracked files match that commit exactly. The complete
`source-manifest.sha256` has SHA-256
`2a4313134171d13c68754ce62db306f9285992ce0134ef7cb529967458f15590`;
all entries verified inside the task-only rootfs. The core pending-multipart
producer/runtime and genuine f828 helper are from accepted core commit `86f25e7`;
six public facades are from `6c2c2cb`; the installed test and guarded runners
are from `0644aaf`. The f828 reference source is
`f828b6c50a0a58d1e718af90f653b214adcc3328`.

The build used the copied task-only rootfs at
`.build-artifacts/pending-multipart-0644aaf/rootfs-v2`, with source at
`/work/sdk-pending-multipart` and its own copied Cargo target. Its reviewed
outer runner is `tests/run-installed-historical-pending-multipart-build.sh`
(SHA-256 `b1b37c39b283286127a287dd5a85bd9a60ef5443328b93b1b7f2bd37b44af6bb`);
the inner script SHA-256 is
`5c1aa011f6582e65a7a453d1374401b1c9c6527349f263bf68da5141bfb59f62`.
The exact successful command was
`bash rootfs-v2/work/sdk-pending-multipart/tests/run-installed-historical-pending-multipart-build.sh rootfs-v2`,
with both paths resolved beneath the task artifact directory. Session `85332`
exited 0; `build-v2.log` SHA-256 is
`213dc0b200ee7497255ad384d7bb5fed8e828a5c2452158f9b9bb0940016da7b`.
The inner script required glibc 2.28, Rust 1.89.0, offline locked Cargo, and
built the CLI, Node addon, and manylinux_2_28 Python wheel.

The reviewed outer/inner install scripts have SHA-256
`617b5daf7cfa8a912393029ccdb67f9245884afc7a01799fa735fea16ece174e` and
`24927a209c2873876c0a8c756c4735aea4805a2c5f0a649764e9dc1950da8c48`.
Session `29739` exited 0 using offline, scripts-disabled npm package/install and
`pip --no-index --no-deps --target`, then imported Python and Node and ran CLI
help in the rootfs. `install-v2.log` SHA-256 is
`66e118e0d6f80e8cea22e04ebf72d8ece26c1898094b6e9897bf85fd984d0f80`.
The wheel RECORD check covered all 10 entries and verified 9 hashes; it
contains `py.typed`. This is wheel integrity/installation evidence, separate
from a static type checker run.

Nine full artifact hashes and paths are in
`.build-artifacts/pending-multipart-0644aaf/artifact-manifest-v2.sha256`
(manifest SHA-256
`00bbf641647cf6de0e51e106a6a3b2576049a44b72f0b755e7283573bc3d982c`);
`sha256sum -c` passed every entry. The CLI hash is
`b3866bbd3678d88584f6877939ada4e13d400126f3d78a63d30c513e1858ce4e`,
the wheel hash is
`ff5596bc414009a559a6226d22797144bd8bad7b99d6aec9c67027d474a7a1e5`,
and the packaged and installed Node addon hash is
`44d55bcc9551f2f09a497b510352adae3affeffaad4196af3beb8c29de5172c3`.
The facade/platform tarballs and installed Python extension are pinned in the
same manifest. `elf-v2.txt` SHA-256
`99f4945763f0f268ed28092459482198414d9662dfc6a465065a81accb1b29f2`
records all three ELF `NEEDED` lists. Each has maximum symbol requirements
GLIBC_2.28, GLIBCXX_3.4.11, and CXXABI_1.3.8. The listed glibc,
`libstdc++`, and `libgcc_s` dependencies remain real; this is not a
zero-dependency package claim. Installed consumers do not use the build-only
`LD_LIBRARY_PATH`.

Preparation failures remain separate from the accepted build. An initial
reflink copy exited 1 because the filesystem did not support reflinks. A
following ordinary sandbox copy exited 1 after its cleanup could not remove
protected partial rootfs files and the base copy could not read protected
`/etc/shadow`/`gshadow`; its `rootfs-copy.log` SHA-256 is
`ac67e969e74e9bba5df8469d697ea3bc7fc6835d79126a4a899bcbff7dea815c`.
Neither reached compilation. A fresh rootfs-v2 copy under the established
local execution route exited 0, verified all 399 source files, and never
mutated the accepted base rootfs or earlier artifacts. An initial ELF
inspection lacked `rg` and produced an invalid all-`none` report; the
corrected `grep` report above is the only ELF evidence.

The first installed invocation exited 127 before its runner started because
it used rootfs-only `/opt/python/cp311-cp311/bin/python` on the host;
`installed-v2.log` SHA-256 is
`b3408b3107c8952e563ae793939f224a5f20cc61fb1c731bb0d2e8c94addef93`.
The actual host interpreter is `/usr/local/bin/python3`. The next run,
session `18150`, passed the pinned f828 compiler/generated/runtime-dependency
guards, created both host fixtures, and reached Python's public multipart
inspection in glibc 2.28. It then failed before Node inspection/attachment:
the test had placed the roughly 150 KB full material JSON in an environment
variable, exceeding the per-argument `execve` limit (`E2BIG`). No SDK attach
or extra service commit was established by that attempt. Its
`installed-v2-corrected.log` SHA-256 is
`44d1a46748f095ca4570d666b00bd60045f87449ee06c49108154eba5f9aedb6`.

The exact test-only correction is commit `eb1bb6c`, test SHA-256
`37fee78aff0f31008708ecb75547eb89a7aed293c9e22ee2c1e83a6c051946a1`:
the same JSON input is sent to Node over UTF-8 stdin and read from fd 0.
No predicate, product code, package, or fixture was changed. The old state
was preserved as `pending-multipart-state-split-failed18150`; a fresh state
uses the original path. Full 399-file overlay manifest
`source-manifest-overlay-eb1.sha256` SHA-256 is
`9f807e019e776c1a75fe219fad7cfbf7c54e42190ee4eea4a8ffe0b9763fe504`;
it differs from the immutable source manifest in exactly that test file and
verifies all entries. Luna reviewed the exact delta before the new run.

The passing business command was
`/usr/local/bin/python3 rootfs-v2/work/sdk-pending-multipart/tests/run-installed-historical-pending-multipart-host.py rootfs-v2`,
again with both paths beneath the task artifact directory. Session `88384`
exited 0; `installed-v2-stdin.log` SHA-256 is
`485c28cb47d621f64b10680ccf81692dc35d39386b7bb6a236f0476c0755c3e9`.
The
guarded host runner SHA-256 is
`38166a79467b88fc31fa610894a0eb5ebf9edd60512b1f4823d4b1f2ba59b847`;
the guest consumer SHA-256 is
`eaceb5247ced10079b156148819432ba4522a4861a449ed96e6341f96fb569e1`.
They pin the f828 generated/compiler/runtime closure, map only three
test-created protected source paths into the guest, and run installed SDK
consumers against the host's same-network-namespace reference service.
No host `/proc` bind or raw key/packet output is involved. The test fixture
creates and reads its protected state, PEM, and SQLite source files and passes
their exact paths; the installed native importer reads those caller-selected
files. The test's SDK consumer does not inspect their bytes or hidden native
state. Both source modes reached `ATTACHED_RESTRICTED`, refused action,
package install, and format transition with exact typed error and no commit,
then reached `ATTACHED` through exact original-command recovery. The applied
mode had one original command commit before attach; the pre-send mode had zero
until explicit recovery. Each recovered full signed SOURCE had four parts;
the test matched every signed part ID, index, source ID, and SHA-256 to the
f828 fixture, required the original command to appear exactly once, and
required exact same-ID recovery to add no commit. The test moved the old
source directory away before recovery/read, used the returned historical
stage ID for native private staged install, and authenticated an installed
protocol and instance readback. Both modes ended at signed sequence 7.

This proves the selected installed multipart handoff and Linux x64 baseline
only. The test uses scripted mixed Python/Node/CLI calls and caller-selected
source pairing; it does not prove independent per-interface completeness,
catalog/publisher discovery, natural Agent instruction compliance, or
macOS/Windows execution. Agent workflow compliance remains separately
unverified and needs an Agent usability/acceptance run regardless of this
business result.
