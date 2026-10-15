# Historical completed install with a later source floor (T-011)

Completed attachment now preserves the original signed END separately from a later selected source/read checkpoint. This fixes the T009 genuine PACKAGE case (installation END5, legitimate public wiki action6), which d47 rejected before PREPARED because it equated completion with source sequence. It does not special-case PACKAGE or accept a checkpoint by ordering alone.

Production checkpoint `e4ae276` adds an optional protected completion tuple `(sequence, head, policy_hash)` only for completed-map plans with a later source floor. The existing verifier independently reconstructs the original exact BEGIN/options/material/staged proof and signed complete END prefix; current PRIVATE Owner/member/key/epoch checks remain mandatory. Attach bounds that proven END by the authenticated source floor; reload compares the entire saved original END tuple and still requires the exact later source checkpoint in signed replay. Completed ATTACHED rows also take this reproof path instead of the ordinary cached shortcut. Pending manifests omit the new field and retain existing bytes/semantics. Legacy completed manifests without it retain their original END==source-floor check. No public DTO/signature or generic selector changes.

Luna's bounded `1878159→e4ae276` production review is clear. Final test source is `bc921f7f889918decd2f2e0820595aed2d7b2fe9`; its only later parent-file change is a test include. The public later-history producer is byte-identical to accepted T009's producer: it completes the original package through public APIs, then performs a legitimate wiki action while preserving the install map and zero pending packets. No state/proof/database surgery is used.

Actual native HTTP gates all passed on one test binary frozen and hash-checked **before and after** execution: `.test-data/completed-read-floor/frozen-runtime`, SHA256 `414ebdeffed986137ebf3885a7c7146bb6582c7b44d6a1f081d6179743f75a25`.

| Gate | Handle | Actual elapsed / result |
|---|---:|---|
| Corrected runtime check |92010|exit0,4.90s|
| Focused native no-run |31396|exit0,34.83s|
| Genuine PACKAGE END5/source6 |87226|PASS1/1;15.091s,08:11:22.337–08:11:37.428UTC|
| No-later PACKAGE END5/source5 |22909|PASS1/1;13.893s,08:11:25.490–08:11:39.383UTC|
| Existing later-rotation refusal |11204|PASS1/1;2.691s,08:11:28.671–08:11:31.362UTC|

Both new cases check wrong selected instance, malformed material through inspect and attach, and stale inspected digest before PREPARED/effects; original source bytes, attachment list, lifecycle absence, service count and observer bytes remain unchanged. They interrupt after PREPARED, remove the complete source directory, then use fresh handles to re-prove and attach. Later history retains exact END5 in its protected plan while reporting/reading ACTIVE6 and the exact signed later record/head. No-later plans omit the context field and remain valid through the legacy loader condition. Repeated completed resume remains idempotent and re-proves completion. The metadata observer file is unchanged across every native operation: zero mutation/reinstall/stage POSTs; service commit counts stay6 or5. Later/plain services were killed and waited successfully, have empty stderr, and their recorded PIDs were absent at report time. The reused rotation test uses its existing temporary cleanup; only its terminal test evidence is retained, not a new raw fixture/PID archive.

The initial check31747 failed E0061 because one pending-plan caller lacked the newly added optional argument; the corrected source passes. Its first error log remains separate and is not attributed as a passing checkpoint. Cache copy completed before compilation; only a task-owned debug target was used. Existing compiler warnings remain. No HTTP attempt failed, no installed cohort was rebuilt or relabeled, and prior d47 T009's refusal remains preserved evidence of the old implementation.

Evidence uses the existing file-record format: `.test-data/completed-read-floor/evidence.json` SHA256 `0677ee9a5e506c04b6444b4f623af520b86420ea712a0cb1c6da11029767bb38` (9 inputs,75 evidence files,1 binary). It includes source exports/protected plans, service SQLite main/WAL, raw observer/producer/service logs, compile logs and exact terminal timing JSON; ephemeral locks/SHM are excluded. Key files are `later-first.log`, `plain-first.log`, `rotation-first.log` and corresponding `.terminal.json`; retained roots are `later-first/` and `plain-first/` under that evidence directory.

T-011 began08:04:49UTC with25-minute budget; production checkpoint was ready08:08:40, frozen binary08:11:01, all actual gates terminal by08:11:39 (6m50 from start). Delivery/integration times are reported separately. This is native scripted recovery evidence, not installed Python/Node/CLI or natural-Agent acceptance. A newly frozen combined installed cohort remains the next separate gate; d47 cannot prove this fix.
