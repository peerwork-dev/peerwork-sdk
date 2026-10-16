# T125 Windows ICU link diagnosis

The Windows ICU collation check in run [38838786286](https://github.com/peerwork-dev/peerwork-sdk/actions/runs/38838786286) failed with five `LNK2019` unresolved ICU symbols. Its archived diagnostic showed all three expected native archives present and all five expected symbols in the source archives, but did not establish whether Cargo bundled those objects into the `peerwork_core` rlib or whether the final MSVC link selected them. The run also showed the GNU core suite passing 104 tests, with the original replay regression passing; separate runtime failures are tracked by the runtime owner.

This change adds failure-only diagnostics to `.github/workflows/distribution-spike.yml`. It preserves the exact Cargo test and exit status, records selected `peerwork_core`/`discovery`/`wire` rustc invocation facts (including `--test`, `--extern`, native search paths, and ICU library flags), requests MSVC `/VERBOSE:LIB`, and checks the five exact symbol names in built `peerwork_core` rlibs as well as source archives. These observations distinguish missing rlib members from link selection without changing product linking behavior or skipping test targets.

Validation: `git diff --check` passed. No local Windows/MSVC execution or PowerShell workflow execution was available, so the cause and any product fix remain unverified pending the hosted Windows job.

References: [Rust external-block linking modifiers](https://doc.rust-lang.org/reference/items/external-blocks.html#linking-modifiers-bundle), [Cargo build-script link directives](https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-lib).
