# T-006 nested implicit source readiness

The installed nested-implicit acceptance case remains **OPEN**. The existing genuine package producer does not yet supply a demonstrated nested protocol source that also satisfies the importer's exact full-material proof contract. No SDK defect or successful installed nested recovery is claimed.

Source: SDK `4dd522b04fcf6446a6eb5762603b6fe706d2e42d`, reference `f828b6c50a0a58d1e718af90f653b214adcc3328`. This isolated change adds only a pure contract witness and this report. The immutable d47 installed cohort was not modified or executed.

The existing producer installs an authenticated dependency and omits the target options' explicit `dependencies`. Its material helper currently supplies one flattened dependency. In reference `src/protocol-compiler.ts:128`, `namespaceManifest` clears dependencies; `compileRaw` explicitly namespaces each already-flattened imported package as one composition unit. Adding another package import level therefore does not demonstrate recursive protocol dependency availability.

The new witness uses the public resolver to insert a genuine middle protocol source declaring the original leaf. `resolveSecureProtocol` and `verifyProtocolComposition` accept the two-node graph. Its executable manifest equals the existing compiled material except for the dependency closure. However, `composeProtocol` preserves that closure in the resolved manifest: the nested digest is `e8500a626c783f5498c3028f9bc44a16e242f836802712ddfd4b45a1e7f8fa2b`, while the unchanged full package material compiles to `7af40ebaaae0cf178e497ae606a4a9df19b1d6fd4918bdd8124a3c6320c9f51f`; composition proofs also differ.

Reference `workspace-protocol-install-plan.ts:54` can obtain omitted dependencies from authenticated protocol objects and their composition sources/nodes. SDK `secure_owner_attach.rs:5965` reconstructs the same availability. That lookup alone is insufficient: `verify_exact_direct_install_begin` at `secure_owner_attach.rs:6445` requires the exact material compiler's protocol digest and canonical composition proof to match the selected source. The candidate above fails those required bindings. It is resolver-valid but invalid for this material-backed import input, rather than evidence that the SDK rejects a valid supported material-backed source.

The bounded next decision is to identify a genuine producer/material representation that satisfies both recursive source resolution and exact package compilation, or explicitly design that representation before another installed test. This investigation does not establish impossibility for every potential representation. Flattened package imports must not be relabeled as nested implicit protocol recovery. PAGE, completed-map and later-history cases were not investigated.

One pure Node witness ran, exit 0, empty stderr; no service, HTTP mutation, native build or recovery ran. There was no failed installed attempt and no retry. Exact command:

```sh
/root/workdir/message/.tools/node-v24.20.0-linux-x64/bin/node tests/nested-implicit-reachability-20261015.mjs /root/workdir/message/.worktrees/e2ee-main-integration-20261006 > .test-data/nested-implicit-reachability/probe.json 2> .test-data/nested-implicit-reachability/probe.stderr
```

Retained evidence: `.test-data/nested-implicit-reachability/evidence.json`, SHA-256 `7ebba810492a2815b051237341effec111baa8041a93efe8df93b1f9d1e3d109`, pins eleven actual source/output files. The full probe output records both source graphs and digests; it contains public protocol material only.

Actual UTC observations: assignment 06:08:07; initial clock 06:08:38; source inspection 06:10:52; completed probe observed 06:12:14; readiness decision sent 06:13:33; evidence frozen 06:14:01. The readiness decision took 5m26s from assignment, within the first ten minutes. Work stopped at this source/material reachability boundary instead of guessing or weakening the acceptance oracle.
