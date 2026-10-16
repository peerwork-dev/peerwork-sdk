# T122 Windows ICU linker diagnostic

The existing Windows failure in run `38835422940` (job `116763360888`) reports five unresolved ICU4C 78 symbols: `udata_setFileAccess_78_peerwork`, `udata_setCommonData_78_peerwork`, `ucol_open_78_peerwork`, `ucol_strcoll_78_peerwork`, and `ucol_close_78_peerwork`. The current evidence does not establish whether Cargo omitted an archive or an archive lacks those public symbols.

The Windows ICU test step in `distribution-spike.yml` now captures verbose Cargo output on the runner and, only after a test failure, emits the selected Rust link directives and linker errors. It checks the three exact MSVC archive paths emitted by `crates/core/build.rs` under `target/debug/build/peerwork-core-*/out/source/icu/source/{stubdata,common,i18n}/x64/Release/`, reports archive presence and size, and filters `dumpbin /linkermember:1` output for the five expected public symbols. The original Cargo test exit status is preserved.

`git diff --check` passed. No local `actionlint`, YAML parser, or PowerShell runtime was available, and this diagnostic has not yet run on Windows; syntax/runtime and the linker cause remain unverified. The existing manual workflow dispatch runs the full experimental matrix.
