# Historical direct-install facades: installed result, 2026-10-14

Status: PASS for the 15 frozen installed cases; the separate integrated source gate also passed. Whole-plan and Agent acceptance remain open.

The frozen Linux x64/glibc-2.28 artifact source is `873a37d85255f570d980f9f73e1df93ee31c0671`, with 463 tracked files. It combines the reviewed Python/Node/CLI facades and corrected outer CLI routes with accepted runtime `618f52eea6639a43743efe8552bdc88e0742fdf0`. The signed-service test overlay is independently frozen at `3030fb61268a93835d7c9c9f05bd2e9d7d394bf6`; it changes no production file or consumer predicate and does not trigger another build. The earlier `06667a7` source-tree snapshot remains a valid tested tree pin for the combination of product `66f06ea` and missing-identity correction `0188`; a report-only commit can pin its source tree without being a new product change.

Build session `37412` exited 101 because copied ICU makefiles named the previous target directory. Its failure log is preserved as `build-cache-path-failure.log`, SHA-256 `8196981d5124a6237c79d9bcd9b35f27c727bf12143dd206c6cdb66b99eb5d94`. Removing only the generated ICU make directory in this task's copied Cargo target resolved that cache relocation; source hashes did not change. Retry `76199` exited 0 (CLI/Node release build 2m02s; Python wheel 27.39s). Fresh offline wheel/npm installation `48722` exited 0. The original immutable e131 artifact cohort was not modified.

Artifact manifest `artifact-manifest.sha256` is `f8f6264e700d91594cd027eb013fabc64dbd8cec527572bcf3a0f5993b190952`; all 14 entries checked. Wheel RECORD verified 9/9 hashed entries. Packaged and installed Python/Node wrappers match frozen tracked source; packaged and installed native binaries match. All three ELF binaries require at most GLIBC 2.28, GLIBCXX 3.4.11, and CXXABI 1.3.8, and retain their documented dynamic system-library dependencies. This establishes this Linux cohort only.

The first host run `41678` exited 1 during the first completed fixture setup before any installed SDK consumer. The old observer attached data listeners, which switched the inner Hono IncomingMessage into flowing mode. Bounded diagnostic `62920` reproduced `SECURE_HTTP_400` and only one service commit; the otherwise identical pinned helper without the observer (`35854`) completed three commits. Both diagnostic services stopped. The first setup failure log is `installed-first-fixture-failure.log`, SHA-256 `c46a8bdb9d2f26c51d93fa390b6461563270df5da3321efb38fc63438a01495b`; its source/DB/logs are preserved under `dist/historical-direct-state-first-fixture-failure`, with observed service exit -15. Child error text was not persisted in this first run, so its exact error is not inferred from that run; the separate bounded diagnostic carries the reproduced error and protected stderr hash.

The corrected observer delegates each request.push call/arguments/return unchanged and adds no data listener. Signed real-service smoke `5188` passed: genuine f828 completed END, two accepted signed outer commit requests with matching inner byte hashes, three service commits, and zero pending packets. The earlier unsigned-4xx-only smoke and source review did not establish signed traffic preservation; that gap is preserved. The corrected host also retains fixture failure stderr mode 0600 instead of discarding child diagnostics. Overlay manifest SHA-256 is `72be949c93af3abdaf7f5c423940e072a9e671e3ba281cba13278bab189a2d41`. Source/archive/artifact manifests were rechecked unchanged before successor run `2237`.

The corrected installed run `2237` exited 0. All 15 cases passed, independently in Python sync, Node native, and CLI; the host terminated and waited for the fixture service before returning. Observed service exit is -15 (intentional SIGTERM), protected stderr empty. The signed-service baseline was 45 commits; final count is 63, with exactly 18 native outer commit POSTs. The service-side summary rechecked every final sequence, accepted selected command exactly once, original signed commit hash, and selected before-send canonical request byte hash. It reads service SQLite and public fixture metadata only, never hidden native state.

Each row below passed independently for all three interfaces:

| Case | Initial → final commits | Native commit POSTs | Selected retained packet |
| --- | --- | --- | --- |
| Completed END map | 3 → 3 | 0 | None; completed inventory binds historical BEGIN and signed END |
| PAGE before send | 3 → 6 | 3 | Accepted once; exact canonical saved request bytes |
| PAGE applied / response loss | 4 → 6 | 2 | Accepted once; selected PAGE not posted again |
| END before send | 2 → 3 | 1 | Accepted once; exact canonical saved request bytes |
| END applied / response loss | 3 → 3 | 0 | Accepted once; explicit recovery without any POST |

Every case refused wrong selected source/options/material and wrong inspected full TS digest before attachment, with no attachment or service POST effect. Retained cases also refused a wrong recovery packet ID. After attachment, the entire original protected source directory (state, PEM, SQLite, options and material) was moved away; fresh handles/processes recovered from only the attachment ID, selected packet ID and config. Completed cases resumed and read back after source removal with zero POSTs. All final readbacks were signed ACTIVE state with the selected instance, protocol digest and entrypoint. Public historical imports stayed absent from ordinary installs(), and repeated completion added no commits or POSTs.

The installed matrix uses Python synchronous methods, Node native typed facade, and native CLI independently in 15 fresh workspaces. Python async routing and Node cancellation forwarding retain their explicit source-test scope; no installed threaded/transport cancellation claim follows. The stable matrix does not add the separate native same-workspace case; accepted core evidence remains scoped to that case.

The native exact-request predicate compares raw observed POST bytes with canonical_wire_value of the saved historical body object (the pinned f828 secureHash). It does not claim identity to the historical TypeScript JSON.stringify HTTP serialization, whose bytes were not retained. Selected PAGE/END packet IDs remain the caller's recovery selection; imported historical BEGIN IDs remain internal except where the completed inventory already exposes them. Ordinary public installs remains empty for tagged historical imports after acceptance.

This is deterministic scripted operator/business evidence. No natural Agent was sampled or restarted. Agent50484's identity-import omission and unsuccessful first attempt remain preserved; this matrix does not close Agent workflow compliance, external acquisition, publication, supported-platform execution, or whole-plan acceptance.

## Separate integrated source gate

Clean isolated integration source `b93433ca523d6cca8de1c3bfb187fc3f019185c7` merges accepted checkpoint candidate `26707f614a127476d2fcee95a6645251119a51a4` with reviewed facade/overlay `3030fb61268a93835d7c9c9f05bd2e9d7d394bf6`. No conflict or public facade/harness change occurred. All six production facade paths and the three installed consumer/host/overlay paths match 3030 exactly; runtime attach SHA-256 is `0852c75e2f820b520291ab6fa36964d320d706cb2c5dbe38c4971b96e7b1d235`, matching 267. Luna and root independently reconciled this merge. This source snapshot is distinct from the installed artifact source 873; the installed 15 cases do not establish whole-snapshot installed acceptance for b934 or the later optional-checkpoint branch.

Focused combined verification `41835` exited 0: Rust 1.89 locked/offline check of runtime, CLI, Python native and Node native (17.32s), then CLI build (28.66s), reusing the task-owned debug cache without another large target copy. The initial commands omitted the copied CARGO_HOME and immediately refused missing offline tokio-macros; both diagnostic logs are preserved. Correcting that environment used the existing cache, no source change or network. Python source routing, Node source routing/AbortSignal forwarding, and actual combined CLI preflight each exited 0 (`f64e6e`, `6d513b`, `90b169`). All eight BEGIN/packet/completed CLI verbs reached typed INPUT_INVALID preflight. Strict TypeScript evidence is reused because the type and consumer source bytes did not change. The combined debug CLI hash is `d76368540f83cc5efe99d3d66676576a4908af9802b791cd03aeb5ed6abca781`.

## Evidence index

All following task-relative files live in `.worktrees/peerwork-sdk-historical-direct-facades-20261014/.build-artifacts/historical-direct-873a37d/` unless specified otherwise. Full protected fixtures and service-side request hashes remain local; the report exports no request body, private material or key.

| Evidence | SHA-256 |
| --- | --- |
| `sdk-source-873a37d.tar` | `d70592dc7c6cd38b3a6edba8eecbcf6132910b92174d5e42469e54d903de5d82` |
| `source-manifest-873a37d.sha256` | `b6edb72d52aa212f9f90b98d7354910f898fe29102c1bb8f68f02f1e9ee79118` |
| `artifact-manifest.sha256` | `f8f6264e700d91594cd027eb013fabc64dbd8cec527572bcf3a0f5993b190952` |
| `build.log` | `d9bb2e3628e7c0dcef37a6482c2aa6eb50263c6afcfd1c350630d3de17340559` |
| `install.log` | `e5096dd2908282521111026470e0d73096d96e7a978611e980de51ea079744c9` |
| `wheel-record.json` | `7cb023781bf620d3b50bc13af39b5b0c5eee4482b39a06a9e296ad8f6b0ebf71` |
| `elf-report.json` | `ed8bb56ad81a6f5a8247c70e3fcced202d8c1e9ec0ece95ec7078bdee246275a` |
| `test-overlay-3030fb6.sha256` | `72be949c93af3abdaf7f5c423940e072a9e671e3ba281cba13278bab189a2d41` |
| `installed.log` | `95663cd4fd076370314cd107b6d3cfc17bc9ee198ed2bc525b9e98d0a337736e` |
| `installed-effects-summary.json` | `d8657e3582e8676986010f595899e3ce821da68f0bb186265fb4c1f2f3b21726` |
| `observer-signed-fixed.log` | `264ceee80536a3d3d8b4811606aa9bf4695368ea00993ef3648710168b31abc3` |
| `integrated-check.log` | `3fca1f14ae927d207528aa38794fb271de3a30f8946edcada98b36fb7622c34b` |
| `integrated-cli-build.log` | `74d20b853572d89ec51c050832da6df90efd2915e329a02ab2aaf46c8b722c0f` |
| `integrated-cli-preflight.log` | `f7141404b44c6a628bfd365dc3b83fa9fe93ee13088391faf01b531878eca978` |
| `integrated-python-routing.log` | `c6a347213673b4454f401f95114a7393367cfcdb57ba78fd347ed24eff6569dc` |
| `integrated-node-routing.log` | `41d6b1a4d97467623c59d0fcad1fa112805ae64c201ed301257ebfe2950877ff` |
| `integrated-check-first-cache-env-failure.log` | `dcdd9fc1dff2dd5d273cd50f878e3f5d3617bb3825e2985755748562b9f2840f` |
| `integrated-cli-build-first-cache-env-failure.log` | `dcdd9fc1dff2dd5d273cd50f878e3f5d3617bb3825e2985755748562b9f2840f` |

Resume: the root-authorized public facade package has implemented and reviewed source, one scoped frozen Linux installed cohort, and a separately verified integrated source snapshot. Main integration remains root-coordinated; this implementer did not write the shared main/index. Final publication, remaining supported-platform/image/upgrade gates, real async/transport cancellation, natural-Agent workflow compliance and public acquisition remain open. Original Agent50484's failure, proxy causality uncertainty, skipped import and preserved synthetic scorecard row are not converted to a pass by these deterministic results.
