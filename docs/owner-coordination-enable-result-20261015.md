# Dedicated coordination enable result

Implemented existing-workspace Owner coordination enable for ordinary PRIVATE and PUBLIC profiles. Product checkpoint `833d88c3219882746dde21e8e93ca3f9af3e0530` is based on accepted SDK `c4e6ac8`. The frozen native API matches the separately implemented facade contract; generic coordination installation exclusions and broad capability flags are unchanged.

The dedicated input denies unknown fields and accepts only optional version and participant IDs. Version omission means 1, matching f828 `enableCoordination`. Omitted participants selects Owner for a new install and imposes no additional requested-participant check on an existing instance. Explicit empty participants means the explicit Owner set. Supplied participants must be unique, valid IDs and existing signed members. Material, grants, visibility, keys and source authority cannot be supplied or overridden. The exact pinned presets are v1 `644b0a3b04d972f10d4937ba866ac515841a3965231841ed7eb6b43736705291` and v2 `24cce0e02c45390f3ecb8efdca92509f6413da42656a7ce2445ad0bc7711ef76`.

A protected operation saves its original signed checkpoint/options, fresh instance and original BEGIN ID, then each exact BEGIN/PAGE/END request before POST. Resume reconstructs the authenticated original prefix, rederives the preset/policy/snapshot and verifies saved signatures, context and decrypted operation before effects. It checks current origin, identity, Owner key and epoch, reconciles already applied packets, and completes only after signed END and ACTIVE replay. An already enabled no-op with no native operation has null command IDs; native operations retain their original BEGIN ID. Previous records, protocol history, unrelated scopes and protection survive; v1→v2 changes only the coordination version/instance/digest, adds the selected new scopes, and retains prior coordination settings. Missing identity remains a strict failure before profile creation.

## Actual verification

All commands used task-owned output, Rust 1.89, the same frozen test executable, pinned f828 source and its checked 204-file compiled closure. No installed cohort was rebuilt.

| Gate | Owned handle / result | Scope |
|---|---|---|
| Initial affected core/runtime check | 51519, exit 0, 28.74s | Original a238 product before the source refinements below |
| First native no-run | 10458, exit 0, 51.17s | Added latest-declaration/identity refinements and HTTP tests, before formatting |
| Frozen-source no-run | 48816, exit 0, 14.62s | Exact 833d source |
| Input / identity controls | exit 0, 1/1, 0.24s | Default v1, omission vs empty, unknown fields, invalid version, enable/resume/operations refuse missing identity without creating its parent |
| PRIVATE HTTP | 73661, exit 0, 1/1, 86.39s | Existing v3/NONE PRIVATE workspace, prior Wiki data, genuine admitted member; coordination v1 lost-BEGIN-reply/reopen recovery; ACTIVE 3→7; v2 upgrade ACTIVE 11 |
| PUBLIC HTTP | 21920, exit 0, 1/1, 81.92s | Existing v3/STRUCTURED PUBLIC workspace and prior Wiki data; same lost-reply/reopen and v2 upgrade; ACTIVE 2→6→10 |

Both HTTP cases passed on the first execution. Each uses a distinct genuine public-client-produced workspace and native historical attachment, then only native dedicated coordination operations. Before enabling, the nonmember refusal leaves service commit count and native operation history unchanged. While v1 is pending, a changed-version request conflicts without an accepted effect. Repeats after ACTIVE, explicit conflicting participants, downgrade to v1 after v2, and accepted-operation resume leave accepted commit counts unchanged. The tests bind original BEGIN identities through reopen and independently verified signed replay, assert the final preset/config, selected member scopes, preservation of all earlier scopes and coordination settings, previous protocol protection, and exact prior record.

Each install uses BEGIN, one record PAGE, one head PAGE and END. The retained public signed-read outputs and an offline read-only comparison additionally confirm the exact original record after both versions and historical Wiki instance revisions `[1,2]`. Thus policy declarations use the latest instance revision while the data snapshot retains history. Service counts prove no additional accepted effects on repeats/refusals; this package does not claim an independent HTTP no-repost observation.

Both reference server children were killed and waited by the owned Rust Drop guard (recorded SIGKILL); both server stderr files are empty. PRIVATE producer stderr retains Node's experimental WebCrypto warning, not a service failure. The protected raw signed reads, source exports, service SQLite plus WAL, operation histories and logs remain under the task target. SQLite SHM is ephemeral and excluded; no checkpoint/vacuum or database edits were used for the fixture or gate.

## Source findings and limits

Before any service execution, source inspection identified that structure declaration derivation must select the latest protocol/instance rows, matching the adjacent installation helper, while snapshot projection uses complete prior objects. That was corrected and is exercised by the genuine prior Wiki action; it was not an observed HTTP failure. Resume was also tightened to open the existing identity before profile initialization. Luna cleared a238's authority/persistence path; the bounded successor delta review was requested and is pending at this report freeze. The initially guessed pinned rustfmt path was absent; system rustfmt 1.8 formatted only the two new files, followed by the frozen-source no-run. No test failure was discarded or relabeled.

Creation-time coordination acceptance remains open: these are existing-workspace tests, not genesis-option execution proof. This package does not claim installed Python/Node/CLI service acceptance, platform/release coverage, cancellation HTTP acceptance, broad option cross-products, downstream coordination actions, or natural Agent compliance. The separate facade report scopes its own source/compile/routing checks. No new Actor, external service, or migration family was started.

## Frozen evidence

Task directory: `/root/workdir/message/.worktrees/peerwork-sdk-owner-coordination-enable-20261015`.

- Evidence manifest `.build-target/coordination-evidence.json`, SHA-256 `f9e2b4f8a60c5339ae9a700feef5ee49a50fa17e508a32b36ec06ce654da0dbe`: 12 inputs, 40 evidence files, 1 binary (absolute paths, SHA-256 and byte sizes).
- Frozen executable `.build-target/coordination-runtime-833d88c`, SHA-256 `de75598b0df4b34817b43ed68756a3a7cdd49deaaffdac8c2bef5aba67d025c4`, 169,694,696 bytes.
- Summary `.build-target/coordination-summary.json`, SHA-256 `16663a45451ce4923a04295fbc17b1b14f0f48ee1e4b2e52727b76659022efa9`.
- PRIVATE log `.build-target/coordination-private-first.log`, SHA-256 `65026d1acfead87ca5096f66881d03a0edda9c5850afeb80bf6b3b9f9115c532`.
- PUBLIC log `.build-target/coordination-public-first.log`, SHA-256 `147e65e96c13343bf3f40272b7d52418418f5203894df13bdaada4c639174942`.
