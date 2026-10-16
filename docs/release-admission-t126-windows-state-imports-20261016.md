# T126 Windows secure-state compile prerequisite (2026-10-16)

The Windows experimental job `116803807732` passed the ICU link discriminator and then failed the workspace build in `secure_state.rs`: `fs` was unresolved in `missing_in_private_parent` and its test, and `OpenOptions` was undeclared in `bounded_secret_snapshot_rejects_growth_and_oversize`. The prior import block gated `fs`, `OpenOptions`, and `std::io::Write` on `not(windows)`, while the Windows test uses all three and Windows production uses `fs::symlink_metadata` in `missing_in_private_parent`.

The import change makes `std::fs` available on all targets and keeps `OpenOptions` and `Write` available on non-Windows production or any test build. No state checks, file operations, permissions, or identity lifecycle behavior changed. Source: `crates/runtime/src/secure_state.rs`.

Rustfmt parse, the exact cfg/import inspection, and diff checks passed before handoff. No local Windows compile or test was available; the next hosted Windows job must establish that this source compiles and proceeds through workspace tests and the CLI, Python, and Node final builds. This is a compile prerequisite, not a final Windows or release pass.
