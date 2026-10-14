# Installed historical direct Python async result, 2026-10-14

PASS for two bounded cases on the unchanged frozen `873a37d85255f570d980f9f73e1df93ee31c0671` Linux x64/glibc-2.28 installed wheel. Actual Python async methods ran through the existing threaded native wrapper; no wrapper/native boundary was mocked, no product changed or rebuilt, and the 15-case matrix was not repeated. Artifact manifest remains `f8f6264e700d91594cd027eb013fabc64dbd8cec527572bcf3a0f5993b190952`; all source/artifact guards were checked before and after.

The first two-case run `44604` exited 1. Its completed-map case passed actual inspect_completed_direct_install_async, attach_completed_direct_install_async, and fresh public async history/resume/read, signed ACTIVE sequence 3, empty ordinary imported installs and zero native commit POSTs. The retained END case reached the controlled after-apply cancellation and fresh restricted history, then failed my test's expectation that resume advances sequence to 3. Frozen source returns the saved summary unchanged for an already attached incomplete imported row; independent review confirmed this. A public CLI history diagnostic found ATTACHED_RESTRICTED sequence 2 while the service had sequence 3, selected command count 1, and one exact canonical native POST. The first log, source-gone state, public diagnostic and effects are preserved; the service stopped with observed exit -15 and empty stderr. This was a test oracle error, not a product failure. Prior design/source review did not catch that sequence assumption.

Test-only `1dbfa1e1005ac07fd028db2ef4bd7e16b0f06708` requires exact equality to fresh saved history at sequence 2, while preserving the final ATTACHED/ACCEPTED sequence-3 and exact single-POST predicates. Its explicit retained-only scope was reviewed and reran only the affected case. The unchanged completed case proof is reused from 44604; the first process is not reported as passing.

Retained-only run `6481` exited 0. Installed inspect_pending_direct_install_packet_async and attach_pending_direct_install_packet_async selected the exact original END-before-send packet and returned restricted attachment at sequence 2. The entire original protected source directory (state, PEM, SQLite, options and material) was moved away; subsequent public calls passed only config, attachment ID and selected packet ID. recover_pending_direct_install_packet_async posted the saved END through the real service. The existing fixture held its successful response after application; the test waited for its started event and independently confirmed service sequence 3/selected count 1 before cancelling twice. The caller received CancelledError. A fresh public attachments_async query and resume_attachment_async verified the saved restricted sequence-2 row. Explicit fresh packet recovery alone then returned ATTACHED/ACCEPTED at sequence 3. Fresh signed read verified ACTIVE, the selected instance, protocol digest and entrypoint. Repeated exact recovery/resume added no effect; tagged historical imports remained absent from ordinary installs_async.

The service-only final oracle found exactly one native outer commit POST, with raw method/path/body hash equal to canonical saved original source.body, selected signed commit hash unchanged, and selected command accepted exactly once. No historical TS JSON.stringify HTTP-byte identity is claimed. The host terminated and waited for the fixture service before returning; observed exit is -15 and stderr is empty. All owned handles are terminal, and no fixture service remains live.

## Evidence

Files are task-relative to `.worktrees/peerwork-sdk-historical-direct-facades-20261014/.build-artifacts/historical-direct-873a37d/`; protected fixtures are not exported.

| File | SHA-256 |
| --- | --- |
| `async-overlay-3b8fc99.sha256` | `3100aad43f8dc270346daab56e1f7412ceb28597ab062265a962f723e84e70ac` |
| `async-overlay-1dbfa1e.sha256` | `7de9e256720e01a405d5a898658411bb8b1502de84defda73531d1ae5d6737af` |
| `installed-async-first-resume-oracle-failure.log` | `9febd0b5744ceed131a8de75670f8b758bb3cc5796c5a7a3c1cfb101aa6fed4c` |
| `async-first-effects.json` | `d441767f4f67bfd1aa602bb4c1e83f581dd8d602566de1b8b47f30f6f41263df` |
| `installed-async.log` | `c680ea29a244823c6d72fd5d72725950f0419fa4590bf4e5c9bc6c865bf9e35c` |
| `installed-async-effects-summary.json` | `42bea2924e51140db9bdd0182f3554d8eac9b1ea50adc079f6fba67cad404be3` |

Resume: the source-only async routing gap is closed for these actual installed completed-map calls and this after-persist/after-apply packet cancellation/source-gone recovery disposition. This does not prove pre-persist cancellation, generated-ID loss, statistical scheduling behavior, real Node AbortSignal cancellation, every Python async method, or the later main runtime source. Workflow compliance remains NOT_TESTED_SCRIPTED_OPERATOR; business correctness is PASS for the two scoped cases. No natural Agent ran, and remaining platform, publication, acquisition and whole-plan gates stay open. Main production bytes remain unchanged; this package contains test/design/result files only.
