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

Review of the first source checkpoint found the persistent lock handle
granted delete sharing. Another process could move its pathname and create a
different lock file while the original guard was live. The follow-up opens
only the persistent lock handle without `FILE_SHARE_DELETE`; the Windows
regression requires rename and deletion to fail and an independent process
to observe Busy. The review also found an inherit-only ACE could pass the
single-user DACL inspection even though it grants no effective access, and
that a reparse ancestor could redirect a final-component-checked path. The
follow-up rejects inherit-only/unsupported ACE flags and walks ancestors of
local-drive paths to reject reparse points. Windows tests now exercise
inherit-only ACL refusal and, when symlink creation is permitted, ancestor
reparse refusal. These source corrections pass
isolated Windows-target type-check, but have not run on Windows.

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
UNC/network state paths are currently refused by the local-drive path policy;
their locking and durability semantics require a separate target contract.
The public SDK capability manifest must continue to label Windows durable
state and secure-agent behavior as unverified until those gates pass.
