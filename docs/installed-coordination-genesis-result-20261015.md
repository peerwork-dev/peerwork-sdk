# Installed coordination genesis result

Corrected deterministic run `23482` exited 0: Python PRIVATE/v1, Node PUBLIC/v2 and CLI PRIVATE/v2 all passed actual create, signed replay and same-command resume using the unchanged installed SDK `d47bbd57f5a1e374d6e60cb8f8aa1c565f9c3559` cohort. Test source is `05d453822a98f15316828f7b895923cb15580316`; no product change or rebuild was needed. Historical total and per-case elapsed durations were not recorded and remain unknown.

| Installed interface | Visibility / coordination version | Corrected outcome |
|---|---|---|
| Python sync | PRIVATE / 1 | CREATED, signed ACTIVE sequence 1, resume idempotent |
| Node | PUBLIC / 2 | CREATED, signed ACTIVE sequence 1, resume idempotent |
| CLI | PRIVATE / 2 | CREATED, signed ACTIVE sequence 1, resume idempotent |

Each case starts with an absent native state leaf, imports its independently generated operator-selected Ed25519 PEM through that interface, and checks exact actor/key IDs before and after creation. Public create selects the existing coordination option. Verified reads bind workspace, head, policy hash, ACTIVE structure, visibility, Owner, seven preset protocols/instances, and the exact coordination preset/instance/state. The hash-bound signed policy has the exact default coordination configuration and Owner actions/roles/capabilities. V1 uses `644b0a3b04d972f10d4937ba866ac515841a3965231841ed7eb6b43736705291`; v2 uses `24cce0e02c45390f3ecb8efdca92509f6413da42656a7ce2445ad0bc7711ef76`.

Every case has one workspace, one accepted `secure.bootstrap` commit, one observed bootstrap POST, and no separate coordination install. The observer reuses the existing pass-through `request.push` primitive with only its route predicate extended to include the bootstrap endpoint. The exact POST method/path/command/length/body hash is bound to the accepted service commit and policy artifacts. A fresh original-command resume returns the same CREATED tuple and verified read with no new request, workspace or commit. Policy artifacts are inspected only after their SHA-256 equals the public verified-read policy hash; this is not a separate policy-signature verifier. Consumers never inspect hidden native state.

The initial run `57296` exited 1 in all three cases at the same late history assertion. Selected identity, CREATED sequence 1, signed ACTIVE/configuration/preset/scopes and exact bootstrap request assertions had already passed. `operations()` correctly returns protected local history with `status: CREATED_LOCAL`; the test incorrectly compared it to fresh `status: CREATED`. The saved tuples differ only in that field. The final coordination-operations and same-command resume assertions had not executed and are unverified for that initial run. The single-line test correction expects exactly the original tuple with only `status: CREATED_LOCAL`; the affected three cases were then rerun in fresh independent directories on the same artifacts and completed. Initial source `9ae54aa`, failed logs, raw calls, effects in service DB/WAL and original overlay are retained; the first run is not relabeled as a pass.

All six reference service children were terminated and waited with exit `-15`; service stderr is empty. No independent PID-absence probe is claimed. Cohort source/artifact guards passed initially and after each service on both runs (610 source files, 14 artifacts). The runner remains a separately frozen overlay. Protected source PEMs, raw public API calls, observer metadata, service SQLite main/WAL, summaries and corrected signed reads/policies remain retained. Ephemeral SQLite SHM is excluded; no checkpoint, vacuum or manual database/state changes were used.

This is scripted API correctness evidence, separate from untested natural Agent workflow compliance and business completion. It covers the three listed creation selections, not the complete visibility/version/interface Cartesian matrix, async cancellation, downstream coordination actions or other platforms. There is no unresolved blocker in the exercised cases.

Evidence is under `/root/workdir/message/.worktrees/peerwork-sdk-installed-coordination-genesis-20261015`:

- Existing `.build-target/coordination-genesis-evidence.json`, SHA-256 `9fcdf65627099764ddcde2ec4a830fc78d510cab2112900c0fd05653817973d6`: 6 inputs and 103 evidence files with absolute paths, sizes and hashes.
- Failed `.build-target/coordination-genesis-first.log`, SHA-256 `a498521deb7e80c4f252449c0a31eb2c306ea3d9c174e735ab9e3a21292cffcc`; corrected `.build-target/coordination-genesis-corrected.log`, SHA-256 `0f949d2b1145d489874f3d9334aa07100382b1c3339fd86f09efc390e572d055`.
- Under the cohort's `rootfs/work/`: `coordination-genesis-d47-first/summary.json`, SHA-256 `7cb324db54503b81ad0c41f04b20b051de0f40ff2ce9d1163d7cc96ca8bda042`; `coordination-genesis-d47-corrected/summary.json`, SHA-256 `71d43af0f98e09fd7998c52a3b7fa7e49f7644ceecd10696eb2bb593e5877bf5`.
- Cohort base: SDK main `.build-artifacts/coordination-sdk-d47bbd5-20261015`; source manifest `8a86e069375614455106c56ed9506552d1254761ceb1e01af922eb66259cfde8`, artifact manifest `15cb4a56a213cb497c114b3d61a73692bad82b0e1d4f1cf632b1c65ad233466f`.
