# Selected partial object-stage public methods

Python sync/async, Node native/CJS/types, and CLI now expose the accepted Rust-runtime selected-final-object-stage capability. Source checkpoint4a7018751d1a65f152826272143962548a48fed4 changes six facade files and three READMEs; c79676c adds only the local CLI routing test. Core/runtime are byte-identical to accepted b821134, so the native package's actual recovery evidence is reused without another service case.

Python methods are `inspect_pending_object_stage`, `attach_pending_object_stage`, `recover_pending_object_stage` and their `_async` counterparts. Node exposes the corresponding camelCase methods. CLI verbs are `owner-object-stage-inspect`, `owner-object-stage-attach`, `owner-object-stage-recover`. Inspect/attach require explicit source/Owner selection, original stage command, original options and full material; attach also requires the inspected source digest. Recovery keeps the original stage ID while explicitly authorizing the separate saved native BEGIN/continuation. Four typed result fields expose original stage, selected instance, restricted/completed status, and distinct native BEGIN. Existing parsers, cancellation workers, and runtime restrictions are reused; no recovery engine or protocol semantics were added.

## Final verification

| Check | Actual outcome |
|---|---|
| Python public sync/async routing and cancellation drain |exit0 with local socket access; exact input strings/IDs/digest, all three operation IDs, worker cancellation and drain before `CancelledError` (stub native boundary)|
| Node public routing/preflight/AbortSignal |PASS marker; exact input strings/IDs/digest, exclusive source selection and native cancel handle (stub boundary)|
| TypeScript7 strict DTO/arity check |exit0; correct inventory/result fields and expected invalid material/arity errors, `--ignoreConfig --module preserve --moduleResolution bundler --types node`|
| CLI/Python-native/Node-native offline compile14961 |exit0,2m41s; normal existing core/runtime warnings|
| Task-owned debug CLI build28925 |exit0,2m47s|
| Actual CLI dispatch, chunk c2658d |exit0; inspect/attach reach `SOURCE_CHANGED` for absent local PEM, recover reaches `NOT_FOUND` in empty history, wrong arity returns `USAGE`; all four expected command exits1|

The checked CLI SHA256 is `0a04b82b43bb73eaf1b4981a0c6bb225b99d709c0b64ff88906093f9c0d849ca`; it is a debug routing artifact, not an installed release cohort. CLI fixtures use only synthetic IDs and absent local source paths; no service or successful attachment is claimed. Exact source/test/build/log/binary hashes are in `.test-data/partial-object-facades/evidence-manifest.json`.

The initial source-only Python batch and its diagnostic copy stalled because the default network sandbox rejects socket-pair `send` with EPERM, preventing asyncio's worker wakeup. The diagnostic shows an idle worker and selector wait. Only those two owned processes were stopped; the same unchanged assertions passed with socket access. The first default-sandbox stop attempt could not address the host PID and delivered no signal; the scoped socket-enabled stop succeeded. Node's test in the original batch passed after the stalled Python child was stopped. The batch's final exit was not used to label the interrupted Python check a pass. Initial TypeScript invocations failed on TS7 configuration/resolution requirements (TS5112, TS5108, TS2835 and missing explicit Node ambient types); all outputs remain retained. The final strict check resolves the declared types and consumes the negative `@ts-expect-error` assertions. None of these setup corrections changed product source or weakened assertions.

Cache copy18443 completed before Cargo;36 copied local Peerwork outputs/fingerprints were invalidated in the separate facade target. Frozen native package targets/binaries/evidence were untouched. All owned compile/test processes are terminal. Luna's substantive source review cleared the dedicated routes, ID/digest/material separation, cancellation reuse, typed status and CLI allowlist/dispatch.

No code blocker remains for integration. Installed Python/Node/CLI partial-stage and enrollment-error evidence is still pending the **one coherent cohort** containing these facades and the separately accepted enrollment fix. Stub routing and compile results do not establish installed behavior, platform support, natural Agent workflow compliance, or business acceptance. The native last-part-only restriction and earlier partial/combined-family gaps remain unchanged. No additional migration family or independent installed cohort was started.
