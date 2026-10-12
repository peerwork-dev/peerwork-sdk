# Windows protected-storage source checkpoint, 2026-10-12

`crates/runtime/src/windows_fs.rs` is shared by the opaque secure-state file
and the SQLite kernel-intent journal. It creates a dedicated state directory
with a protected current-user DACL, then checks opened handles for current
user ownership, one current-user full-access ACE, no reparse point, and one
hard link for files. The journal checks existing WAL, SHM, and rollback
sidecars before and after opening WAL mode. The secure state holds an
exclusive nonblocking file lock for its lifetime and guards operations and
explicit unlock with the creator PID. It writes a same-directory temporary
file, syncs its content, and requests a write-through replacement. The
Windows tests cover private-directory/file refusal, exact-byte replacement,
and a separate-process lock probe. The Windows runner must execute these
tests; a source-level cross-check does not establish their behavior.

A task-local Rust 1.89 Windows GNU standard-library target was installed.
An isolated `cargo check --tests --target x86_64-pc-windows-gnu` of the shared
filesystem module and secure-state module passed, including Windows test
source. Checking the whole runtime target stopped in `libsqlite3-sys` before
the runtime compiled because this Linux builder has no
`x86_64-w64-mingw32-gcc`. The exact failure was the bundled SQLite C build's
`ToolNotFound` for that compiler. There has been no Windows execution or
Windows runtime binary from this checkpoint.

On a real Windows runner, verify ACL inheritance and tampering, reparse and
hard-link rejection, noninherited lock handles, independent-process lock
exclusion, SQLite sidecar permissions, simultaneous journal writers,
replacement after power-loss-like interruption, and native-store migration.
The source requests `MOVEFILE_WRITE_THROUGH` after flushing file contents;
the complete crash-durability contract, including directory metadata, is
unverified. TypeScript-state backup/readback migration is also still open.
The public SDK capability manifest must continue to label Windows durable
state and secure-agent behavior as unverified until those gates pass.
