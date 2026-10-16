# T114: actual-service release gate wiring

Source base: SDK `72f0b417ea1fc2e9338d4e35ea4e62ee95b43140` (production
`0daef2a865bc3b09b7c76274883d47680668051c`). This package changes only
the release workflow, builder wiring and installed workflow helper. It does
not build final target packages, publish artifacts or modify the service.

**Basis and decision.** The release promises installed native packages on
seven targets that can perform a verified current-service action. The existing
release builder only ran offline installed identity smoke, so a successful
candidate could have no actual-service evidence. The new gate makes an
unconfigured or failed replica-1 target block candidate assembly and therefore
publication. Replica 2 remains the independent byte reproduction, avoiding
fourteen duplicate service workflows.

**Method and end.** The smallest representative business journey is the
existing installed Owner/adopter composed workflow: fresh identities, signed
genesis and reopen, package install, distinct recipient enrollment/admission,
proposal, adoption, task and exact signed readback through Python, Node and
CLI. The external mode removes only development control endpoints for dropped
responses and counters. No legacy migration, load, depth, browser or Agent
trial was added. An isolated service endpoint and source assertion are explicit
operator inputs, described in `docs/release-service-acceptance.md`.

One affected actual HTTP run used the immutable T097 GNU x64 installed wheel,
npm packages and CLI, version `0.0.1`, with SDK source/vector unchanged between
its production input and this source. The server was the locally pinned
`f828b6c50a0a58d1e718af90f653b214adcc3328` integration checkout,
launched through `tests/reference-kernel-server.mjs`, which checks its source,
compiler and compiled closure before serving loopback HTTP. The corrected
external-mode helper exited 0 in 10.871 s. It observed distinct Owner and
recipient actors, two PAGE and two END install steps, one proposal candidate,
one adopted exact candidate revision, one task related to that candidate, and
verified final sequence 10. The installed Node and CLI paths were exercised;
CLI retries returned the accepted operation without advancing the signed head.
Public result metadata is retained in
`/tmp/t114-release-service-20261016/result5.json` and
`/tmp/t114-release-service-20261016/gate5.stdout`.

First failures remain separate. The first local launch stopped before service
startup because sandboxed Node `spawnSync git` returned `EPERM`; no HTTP or
workspace effect occurred. A changed execution context permitted the pinned
service to start. Its first installed run stopped on normal
`ENROLLMENT_PENDING` before workspace preparation; the helper now retries the
same protected Owner identity, as the public error instructs. The next run
reached signed genesis but an overstrict helper assertion expected `CREATED`
where the local operations DTO reports `CREATED_LOCAL`. A fresh, narrow
prepare/resume/operations probe confirmed `ENROLLMENT_PENDING`, then `PENDING`,
`CREATED`, and one `CREATED_LOCAL` row before that assertion was corrected. The
two failed installed traces and the probe are retained under the same `/tmp`
directory. This was test-oracle/runtime setup cost, not evidence of a product
defect or a repeatedly sampled business pass.

Static checks: Python compilation, `git diff --check` and pinned
`actionlint` on both release workflows passed; configuration
checks accepted an explicitly scoped HTTPS origin and rejected missing source,
unsafe HTTP and non-isolated scope. `python3 tests/release-workflows.py` passed
12/12 in 4.277 s. Seven hosted native target
executions, the configured endpoint's independent source binding and final
`0.1.0` candidate execution remain unverified. The local pass is a scripted
business/runtime result; Agent entry/workflow compliance was not tested.
