# Caller-selected complete replay count (T079)

The native read stack now accepts `max_replay_commits` (positive u64 representable as usize; default **102400**, unchanged). The core `replay_secure_journal_exact_with_limits` carries one limit through archived-prefix reconstruction, recursive recovery and final signed-header scanning; the old entrypoint keeps its default. Signed source sequence plus incoming count is checked with overflow protection before prefix allocation. Incoming transport collection and protected prefix reproof use the same selected count. Existing wire-byte, policies, signature, source, fragment, format and authority guards remain intact.

Runtime read/profile, Owner, invitation/grant and dependent client configs propagate the option without changing persisted profile/history schemas. CLI secure-read accepts `--max-replay-commits=COUNT`; Owner JSON help lists the optional field. The minimal protected `load_config` result remains origin/state_dir: resource options belong to the explicit client constructors/config DTOs. Pure Python/Node routing is the separately reviewed T080 component, not owned by this change.

## Actual verification

The existing T059/T063 synthetic archived fixture was reopened at its exact origin/receipt seed/profile through public APIs, with original source exports absent. No producer or new attachment was created. The reviewed public Python wrapper from T080 commit `31ebe90f83448d80894cac46fb0d9551519ca20f` (SHA c629f6fbae38ce4d50e62be16ab77160c26713a384393ce1e57722e164d553ce) loaded task-built native module SHA **87b57ecfb35cb1bff4a4954cfb3531f0b2937c86ff65ea11118bf2d807355adc**, frozen before execution from Rust **f3a51913fc6f327e4292f6961b1ca5e749030eeb**.

- Limit26 returns `RESOURCE_LIMIT` for 14 incoming / 27 restored commits, with attachment inventory unchanged.
- Limit27 returns exact signed head/policy/27 commits and all25 reference objects; fresh repeat and omitted/default limit return the same result.
- Transport removal of one archived original returns `VERIFICATION_FAILED`; restoring normal transport recovers the original complete result.
- Public constructor rejects 0, negative, bool and out-of-u64 values. Source exports remain absent.
- Actual corrected host11817 exited0, **14:47:49.467–14:48:00.255 UTC (10.788311s)**. Service metadata: 14→14 commits, 5 journal GETs, one removed archived packet, no producer, exact origin/seed, closed and waited.

Core signed archive unit passes (1/1, 0.20s), including low-limit refusal; checked default/zero unit passes (1/1). Final runtime count/byte-budget unit passes (1/1; compile18.21s). Actual CLI Owner-help/invalid-invocation regression passes. The affected CLI/Python build for f3a5191 passes9.47s. Earlier four-package check passes10.32s and initial CLI/Python build passes2m12s. Logs and frozen pins are retained under `.test-data/t079/`.

Final product source after the HTTP-tested f3a5191 is **a5229161ff50106663727cf365bac543372728ba**: one additional error mapping preserves resource errors during a separate Owner bootstrap-profile establishment path. It was independently source-reviewed; the HTTP read path is unchanged. Final verification source **fd6203d74f770b8e21c7943f23988e2cdd9d3a96** additionally updates only two cfg(test) config literals and test sources/help expectation. The runtime unit compiled this final source; the earlier HTTP binary is not relabelled as final-source-built. Distro T081 reviewed the core/propagation delta, grant corrections, historical read correction and final one-line Owner mapping clear. No runtime installed-cohort or new release claim is made.

## Preserved failures and costs

Initial check36142 exited101 because the new ResourceLimit variant was missing from a per-step exhaustive match; corrected check5364 passed. The owned stopped-cache copy unnecessarily invalidated the core build-script/ICU output as well as local code, adding avoidable preparation cost; no old cache/artifacts were changed. Exact initial cache/check duration is unrecorded, not reconstructed.

Reviewer T081 found two grant-reader constructors falling back to default count and error mappings collapsing resource refusals; checkpoint14035 corrected these. First HTTP preflight stopped before service because the T080 report-only amendment changed HEAD3df6→31ebe while wrapper bytes stayed identical. First actual host58855 exited1 in **2.079234s**: limit26 refused but historical Owner mapping incorrectly returned `VERIFICATION_FAILED`. It performed no mutation (14→14), and service closed/waited. The concrete mapping fix produced the corrected pass above on the SAME fixture. First runtime-unit compile80524 exited101 for two omitted test-only config fields; corrected33679 passes. These failures are retained separately.

A service-turn content-filter error interrupted orchestration earlier; it was not a test/product failure. No elapsed budget was reset. T079 started14:29; first compile/check phase began14:33:55; corrected actual gate ended14:48:00; final unit observed complete14:49:23. Remaining historical phase times are unknown. Initial delivery target14:49 was missed while fixing the real error mapping and test-literal omissions; root acceptance deadline remains14:54.

## Evidence and limits

Manifest: `.test-data/t079/evidence.json`; corrected raw records: `corrected/http.log`, `corrected/http-terminal.json`, `corrected/http/continuation-consumer.json`, `corrected/http/continuation-service-exit.json`, `corrected/http/result.json`, `corrected/frozen-local.json`. Original failed records remain at the unsuffixed paths. The original immutable T064 artifact manifest's14 subjects were rehashed unchanged (`old-cohort-guard.json`). Native journal/identity/profile contents were accessed only through the supported client APIs; no DB edits or private extraction occurred.

This proves configurable low restored-count boundaries on authentic signed archived history. It does not prove histories above102400, >64MiB histories, all-interface HTTP parity, other OS behavior, installed release packaging, Agent workflow or publication. Python uses the reviewed pure facade with a locally compiled GNU native module in the existing isolated host-runtime overlay, not a replacement immutable installed release cohort.
