# Owner enrollment causes and explicit runtime handoff

Product `91490e191d594ec2ceb10bdea195884918a563f6` (base `52a449d`) passes the focused runtime and current-CLI HTTP gates. Owner creation now preserves the safe typed enrollment cause and phase instead of collapsing it into `ENROLLMENT_FAILED`. Configuration, transport, discovery status, verification, local state, identity continuity, cancellation, numeric server rejection and saved enrollment pending remain distinct. Messages name explicit proxy/config reconciliation without interpolating configured values or raw errors. Generic proxy variables remain ignored. Existing explicit-create cold start remains; corrupt/unsafe existing identities are never replaced. No bootstrap, permission, signature or transport-policy behavior changed.

Python `OwnerWorkspaceError.code` and Node `error.code` already forward the unchanged native envelope (Python `_owner`, Node `openSecureOwnerWorkspaces`); this is source evidence only. Updated installed Python/Node parity remains queued for one unified candidate. The preserved Wiki Agent failure remains workflow-incomplete/business-unsuccessful with its actual underlying cause unverified; this deterministic test neither reruns nor reclassifies it.

## Executed gates

Owned corrected batch `38098` exited 0, using Rust 1.89 and `CARGO_HOME=/root/workdir/message/.worktrees/peerwork-sdk-native-20261012/.build-target/cargo-home`, `CARGO_TARGET_DIR=$PWD/.build-target`:

```
cargo build --offline --locked -p peerwork-cli
cargo test --offline --locked -p peerwork-runtime --lib owner_enrollment_errors_preserve_cause_and_pending_guidance
cargo test --offline --locked -p peerwork-runtime --lib owner_prepare_refuses_corrupt_or_unsafe_existing_identity_without_replacement
cargo test --offline --locked -p peerwork-runtime --lib enrollment_kernel_causes_are_typed_without_sensitive_error_details
```

CLI build passed in 7.58s; each selected test passed 1/1. Existing unrelated unused-import/dead-code warnings remain. Frozen debug CLI SHA-256: `40d0fb4338e5610f5f737f3a989ad9f91847f6aa9fc30b35a0681425e1d6b7be`.

Owned no-model HTTP run `35179` exited 0 on its first attempt:

```
python3 tests/owner-enrollment-errors/host.py /root/workdir/message/.worktrees/peerwork-sdk-owner-enrollment-errors-20261015/.build-target/frozen-owner-errors-91490e1/peerwork /root/.local/bin/codex /root/workdir/message/.test-data/owner-enrollment-errors-20261015-one
```

The host needed approved outer execution for local binding/child sandbox setup; the child used all 18 archived Wiki policy settings unchanged, with no model, prompt, actor, destination-policy widening or SDK proxy preselection. The genuine pinned f828 reference service/204-module closure was reused. A fresh selected Owner was explicitly imported, then the same identity/config was used throughout:

- Generic runtime proxy variables alone: `TRANSPORT_FAILED`, actionable enrollment-phase guidance, empty workspace operation history and no observed structure-commit POST.
- Malformed explicit proxy containing a synthetic credential marker: `TRANSPORT_CONFIGURATION_INVALID`, no credential marker/user/path in the error and no observed structure-commit POST.
- Explicit `PEERWORK_HTTP_PROXY` selected from the runtime route: `CREATED`, signed PRIVATE workspace/selected Owner/ACTIVE read at sequence 1; same-command resume returned the identical result. Selected native identity bytes stayed unchanged.

Final read-only service counts were exactly one workspace and one `secure.bootstrap` commit. The existing observer covers structure-commit endpoints, not enrollment/bootstrap endpoints; its empty log is not an all-HTTP request count. Owned service terminated/waited with exit -15 and empty stderr. SQLite main **and WAL** are retained; SHM is ephemeral. No frozen c5e/873/8cae cohort was modified.

## Retained evidence and limits

All paths below are relative to this worktree unless absolute. `.build-target/owner-error-evidence.json` contains 51 exact file hashes, SHA-256 `4e324174f46ff53fa5a6b07dbff267bc1edfa06e3224465923744aa0cd28b6af`, including tested source, unchanged facade/CLI forwarding source, frozen binary/metadata, actual logs, protected fixture outputs and SQLite/WAL. HTTP log: `.build-target/owner-error-http-one.log` (`b22567848b560ec615d144dacea191585f34237cbdee96b87b4b8e2ef72e24ad`); task summary: `/root/workdir/message/.test-data/owner-enrollment-errors-20261015-one/summary.json` (`bd69a8389a900a3e14eccf420a51f986f73a98f6f93e5744261a16d94fc24f58`); invocation: same task `invocation.json` (`ef65e3d29a9606995cb5220831147885aa97ffe79ccd3e193a3eec90ca00078e`). Logs/config/evidence are protected; proxy URLs and real credentials are not logged.

Initial owned batch `22021` passed its draft CLI build/three tests, but its draft precheck would have refused missing identity during explicit creation. That behavior and test were removed before HTTP execution; its original source/logs remain in the manifest, and the corrected batch is separately attributed. They are not final-source acceptance. Luna independently cleared the frozen product/error exposure before the HTTP run; no natural-Agent, updated installed three-interface, external destination, platform or publication acceptance is claimed.
