# T076 metadata-only WAL barrier qualification

The own-child Linux/x86_64 tracer is qualified for the narrow test-control boundary. It follows one synchronous child, arms only after a successful `fsync` on the selected backup descriptor, and accepts WAL/frame headers only when their successful writes occur after that arm. It matches the selected WAL through `/proc/<child>/fd/<fd>` and stops at `pwrite64` entry for an eligible payload. It records path matches, offsets, lengths, syscall returns, flags, and terminal status; it never reads child memory or write buffers and does not trace unrelated processes or threads.

The corrected public-dummy qualification passed in the previously approved user+mount namespace without a nested PID namespace:

```sh
unshare --user --map-root-user --mount --fork /bin/bash -euc 'python3 tests/migration-wal-barrier/qualify.py'
```

Exit was 0. The positive child stopped at payload entry after the selected backup `fsync` returned 0, WAL offset 0/length 32 returned 32, and offset 32/length 24 returned 24; payload was offset 56/length 512. Three negatives exited 0 without a barrier: a nonmatching backup, a 511-byte payload, and WAL/frame headers written before the matching backup `fsync`. The last case confirms those earlier headers are cleared when the backup arms the tracer. The output records four terminal child results and no payload data. Retained stdout is `.test-data/t076/qualification-corrected.stdout` (mode 0600, SHA-256 `5b723819b6f183e90aa780fe8528b20a06f95f8c0f0ea273686bc8e1381422db`); stderr is empty (SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).

This successor also fixes cleanup so `finally` only kills and reaps a child that has not already reached a terminal wait status. The fail-fast `/proc` check still confirms that the tracer PID view matches and the forked child is visible before tracing.

The earlier three-child qualification is preserved as superseded evidence. Its source lacked the post-backup header reset and its cleanup unconditionally signaled a child after `waitpid`; root review identified both before any SDK fixture was launched. The corrected four-child run above is the qualifying pin.

Earlier setup/control failures remain distinct: direct default-context ptrace did not reach the child stop; a PID-namespace attempt found `/proc/self/uid_map` read-only (`qualification.stderr`, SHA-256 `731fa347449bfb63ad97dd72dadf5ae4776694f1365e5638d81b7860c7819cfd`); an escalated PID-namespace run lacked matching fd paths because proc remained host-mounted; and remounting proc was denied (`qualification-proc-mount.stderr`, SHA-256 `184a74187354adb50febbcc7c3ca66750ce01ecc2a332ef41a8dda8066035c17`). The successful context omits the extra PID namespace while retaining user+mount isolation and own-child-only tracing.

Corrected source SHA-256 values: `trace.py` `fb90b68aa04afbf1179d30edd0c3d2f04531b1e186af32a493c8d364a1808b83`, `dummy.py` `fd27c14e96f716a7da4b8b8056235aec4a7b195d01769af441007257311290c9`, and `qualify.py` `25f2eb6a522abef56169f7ab95ba22c004a3fb4ba2e5aca8f98d5cda8d4d4022`. `py_compile`, `git diff --check`, and the corrected four-child qualification passed. No SDK migration, service, build, or private-state fixture ran. Actual migration interruption, all-or-none recovery, and retry evidence remain open for the separate owner-controlled gate.
