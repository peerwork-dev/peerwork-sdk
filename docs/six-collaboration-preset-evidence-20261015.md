# Six collaboration preset evidence reconciliation (T070)

All six default collaboration presets already have accepted installed genesis evidence. No missing preset case was found, so T070 ran no HTTP, SDK test, build, download or new fixture. Original plan `docs/sdk-multiplatform-plan-20261012.md:140` requires these six presets with supported creation options; they are not six selectable creation modes. T035 already accepted this distinction (TIME-LEDGER.md:392–399).

The exact public roster is f828 `src/workspace-presets.ts:106`; `workspace-secure-agent.ts:719–722` always creates every default protocol/instance and derives Owner scopes, optionally adding coordination. Native `crates/core/src/bootstrap_objects.rs:13–23,104–149` embeds that finite roster. Current source43ac40d and retained T037 source7dd have byte-identical bootstrap-presets.json, bootstrap_objects.rs and genesis_structure_policy.rs. An initial whole-owner-create equality assumption was false: its sole later diff normalizes the internal lifecycle origin in open_lifecycle (T063); the preset generation path is unchanged. This source reconciliation does not relabel old artifacts as current installed execution.

| Default entrypoint | Pinned digest | Accepted installed evidence |
|---|---|---|
| discussion | `e31188a871138c8065682517931fba8c3fbd288516cda6c7aad88ff70c135c17` | T037 exact full manifest, instance and scope |
| wiki | `05300473589495f96080b96c78962acc0c0ecc8bf1ae82d84f214042a6d30ca2` | T037 exact full manifest, instance and scope |
| task | `834f9b1ee62ad016c1be9067dfaa96dba71cfbacbed02487fe9ab9afcb5f8e50` | T037 exact full manifest, instance and scope |
| hostedService | `81ef3b74557ddaa685318c860374c3de01243f69c18804fe6fbc923c176f62da` | T037 exact full manifest, instance and scope |
| externalService | `84c9b0d5f74522d7b6ad89a1f97c509f49aad1ecac2701c4f93dd1bc2c3defa1` | T037 exact full manifest, instance and scope |
| outputs | `e8bd3597e1f41683a4c579c71694a6784c6acb3c39de50c0b3064144debdad9b` | T037 exact full manifest, instance and scope |

T037 `tests/installed-encrypted-genesis/consumer.py:30–50` binds the accepted signed bootstrap/read policy hash, exactly six protocol and instance objects, each full manifest/resolved manifest, entrypoint/initial state, and exact Owner actions/capabilities/conflict-filtered roles. Its retained corrected read/policy/effects/calls and corrected log were hash-matched against the existing accepted manifest and checked offline again during T070; all six exact matches succeeded. This is existing signed-replay evidence, not a new signature-verifier execution. Source-backed role conflicts are respected, including hostedService; every declared role is not indiscriminately granted.

| Existing acceptance | Actual exercised selection and boundary |
|---|---|
| T004 / docs/installed-coordination-genesis-result-20261015.md | Three independent installed cases: Python PRIVATE/v1, Node PUBLIC/v2, CLI PRIVATE/v2; seven protocols/instances, selected coordination preset/policy, bootstrap POST once, fresh same-command resume/read idempotent. Initial late CREATED_LOCAL history-oracle failure is preserved separately. |
| T037 / docs/installed-keep-encrypted-genesis-result-20261015.md | Installed Python PRIVATE/structured/nonempty keep-encrypted, no coordination; exact six defaults, protected discussion action/readback, original create resume idempotent. Initial scope/declaration/disclosure-oracle failures remain preserved; corrected52845 exit0. |
| T067 / docs/installed-owner-name-result-20261015.md | Current immutable52a installed Python/Node/CLI PUBLIC/unstructured name-boundary creation and signed read/resume, not a second full-six assertion or full creation-options matrix. Harness/collector corrections remain preserved. |

Existing T037 manifest `/root/workdir/message/.worktrees/peerwork-sdk-encrypted-genesis-installed-20261015/.test-data/t037/evidence.json` SHA `7e9bc84cbf75aeb86da33cd217ef718a7294e0b9cbc7849b4737cb03d69c9e8a` pins the original source7dd/artifact85aa and first/corrected outcomes. Corrected retained read SHA `bf28a6f4da0418d59230adec980fe466fdd617b1db490de3ca8bd6d0b637c437`, policy `9ecd48fab417802d938a981e903c7ecf0c575248887f94fd65c436f077c04331`, effects `8d25f26213a7384d41c34f7db4e2cf5e6e9a957fffcb486ca646fd5e04fbb00d`. Exact retained paths plus all six roster checks and current source hashes are in task-owned `.test-data/t070/reconciliation.json`, SHA `4b58ce35a3ffe5368eae77930e5186f969d59171accddcdb75df612ecc8ba19a` (five selected original evidence hashes checked, no new manifest framework).

T070 started13:42:34 UTC; roster decision observed13:43:24, retained-oracle/source reconciliation observation 2026-10-15T13:44:58.063493+00:00 (exact JSON timestamp). No service handles were opened, cleanup was unnecessary, and immutable T064/source759/artifact14 files were untouched. Existing accepted evidence closes the six-default-preset gate only; this does not claim every optional combination, each preset action, Agent workflow, other platforms or publication.
