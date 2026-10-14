# Config-aware Owner identity bootstrap result

The config-aware legacy PEM import now creates the configured `state_dir` leaf when its existing parent is protected, then writes the identity to the configured `identity.state` path. The generic path-based importer remains strict, and identity reads do not create missing state directories. Unix and Windows source checks preserve private-parent, ownership, reparse-point, and protected-leaf checks; Windows execution remains unverified.

The frozen product change is commit `03ab37299c64d2686359794aa9ce18a602b38d58`. Its nine changed source/documentation paths are the runtime Owner creation/state files, CLI, Python and Node bindings/types, and `docs/agent-entry.md`. The source was reviewed at those exact bytes. The documentation wording correction is `e69c411cbc994670ef8793d43dbe640e499f1145`; the smoke assertion correction is `121e284eeb361b47542360b40a504c7e19fc9dc5`.

Validation used Rust 1.89.0 with the existing offline Cargo cache. The focused runtime test `config_aware_identity_import_creates_only_the_configured_private_directory` passed 1/1. `cargo check -p peerwork-cli -p peerwork-python-native -p peerwork-node-native --offline` passed, and `cargo build -p peerwork-cli --offline` produced debug CLI SHA-256 `901269340e3f883f850d0b9dfbb81a876d5cf00e792c9e49b14d2b2995a033f2`. Node syntax, Python byte-compilation, and `git diff --check` passed. Python and Node binding behavior was not exercised against an installed artifact.

The no-model CLI smoke used the frozen debug binary and this exact command:

```text
python3 tests/config-aware-owner-identity-import-smoke.py /root/workdir/message/.test-data/owner-identity-bootstrap-73d020-run1 /root/workdir/message/.worktrees/peerwork-sdk-owner-identity-parent-20261014/.build-target/debug/peerwork /root/.local/bin/codex
```

It ran one config-aware import successfully, confirmed `identity info` returned the same nonempty public actor/key fields, and confirmed reimport refused with `IDENTITY_STATE` without changing the identity. Generic import and info both refused with a missing parent and left it absent. An unsafe existing parent and a symlink leaf were rejected with `IDENTITY_STATE`; neither target leaf was created. The restricted child policy allowed only the local proxy, disabled upstream/SOCKS, web, apps, MCP, and multiagent, and had `PEERWORK_HTTP_PROXY` unset. No model turn or service was involved.

Protected evidence is at `/root/workdir/message/.test-data/owner-identity-bootstrap-73d020-run1/summary.json`, SHA-256 `ee1024d42995829aade28f9e3da5951024702080a3142d41dd216fbef5132b03`. The summary records the CLI hash and outcome booleans; captured outputs and the test PEM remain mode 0600 in the mode 0700 task directory.

This verifies the Linux debug CLI contract and compile/syntax coverage for the Python and Node bindings. It does not establish Windows runtime behavior or installed Python/Node behavior. The earlier synthetic Agent attempt that encountered `IDENTITY_STATE` remains a failed workflow/business attempt; this no-model regression diagnoses and covers the bootstrap contract but does not replace or repeat that Agent evidence.
