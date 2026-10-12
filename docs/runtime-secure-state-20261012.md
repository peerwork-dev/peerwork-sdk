# Native secure-state checkpoint, 2026-10-12

The TypeScript baseline at `dd8a9d2` keeps secure-agent signed packets,
action intents, keys, and checkpoint pins in protected JSON state; it keeps
kernel command receipts in a separate SQLite store. This runtime port keeps
those stores separate. The new `SecureStateStore` is a low-level persistence
boundary only, not a secure-agent implementation or verified action API.

The native file has a distinct version header. Opening an existing TypeScript
JSON state file fails with `MigrationRequired` without rewriting it. On Unix,
the parent must be a real, private directory owned by the current user; the
state and persistent lock file must be private regular files with one link.
An exclusive nonblocking OS file lock remains held for the lifetime of the
store, including while state is replaced. Replacement writes a private
temporary file, flushes it, renames it, then flushes the parent directory.
The stored payload is retained as exact bytes so signed JSON with escaped
UTF-16 surrogate units need not be converted through Rust `String` or
`serde_json::Value`. The 64 MiB state ceiling matches the tracked
`workspace-secure-local-state.ts` file-size bound. Binding facades do not
expose this raw state API.

The source tests exact-byte restart and replacement, legacy-file refusal
without overwrite, symlink refusal, same-process and separate-process lock
exclusion, and a duplicated descriptor retaining the lock file after the
guard drops. The first Rust 1.89.0 parallel suite failed once when a restarted
state unexpectedly found its own lock busy. Isolated and serial tests passed,
but those later passes were not treated as a fix. Explicit `LOCK_UN` before
closing the guard fixes the deterministic duplicated-descriptor mechanism;
the affected regression and full 13-test runtime suite now pass under the
task-local Rust 1.89.0 compiler with `--offline --locked`. The exact timing
of the first parallel failure was not captured, so its process-scheduling
cause remains an inference, not a proven trace.

The store does not parse or authenticate secure-agent state, prove a signed
journal outcome, classify an action intent, or migrate old state. Windows
fails closed until protected ACLs and locks are implemented and tested on a
real Windows runner. No secure-action capability is advertised from this
checkpoint.
