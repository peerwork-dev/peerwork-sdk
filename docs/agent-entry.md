# Agent entry for an existing PRIVATE member

Use the operator-selected installed SDK, identity, service and PRIVATE workspace.
This path requires existing admitted member state and protected workspace
profiles. It does not create an identity or enroll a member. If an input is
missing, report it; do not scan for keys, invent a state directory or substitute
Owner authority. Only when the operator selects an Owner, historical-source or
specialized configuration workflow, follow the
[specialized guide](agent-entry-legacy.md), including its unchanged prerequisites.

The Python/Node equivalents and protected setup are in the
[implementation checkpoint](sdk-agent-runtime-implementation-20261019.md).
The [product design](sdk-agent-runtime-design-20261019.md) describes the broader
target, not a guarantee about your installed artifact.

1. Inspect the exact supplied executable: `peerwork version`,
   `peerwork capabilities`, and `peerwork context --help`. Source presence and
   broad readiness flags do not establish installed command availability.
2. Open the supplied context with
   `peerwork context open PROFILE ACTOR SERVICE`. If a context does not yet
   exist, explicitly bind the selected existing workspace profiles using
   `peerwork context bind PROFILE ACTOR SERVICE bind.json`, where `bind.json`
   contains `{"workspace_profiles":["/selected/existing/member-workspace.json"]}`.
   The target parent must already be protected; bind refuses overwrite and
   creates only the context reference, without copying identities or history.
3. Retain `value.context.fingerprint`. Every subsequent request file must name
   `workspace_id` and carry that `expected_fingerprint` to pin continuity across
   CLI processes. Omitting it is accepted for legacy compatibility but loses
   that continuity check. Python/Node handles inject their opening fingerprint;
   after reopening, compare the descriptor with the retained handoff pin before
   resuming. Keep actor, service and workspace choices unchanged.
4. Read the authorized source and protocol before acting. Use
   `peerwork context discover PROFILE ACTOR SERVICE discover.json`, with
   `query: {"limit":64}`; follow its exact pagination continuation when needed.
   Use `peerwork context describe PROFILE ACTOR SERVICE describe.json`, with
   `query: {"instance_id":"SELECTED_INSTANCE","action_id":"SELECTED_ACTION"}`,
   for verified protocol, schema and authority information. Scope summaries are
   advisory (`execution: "not_evaluated"`), not permission to execute. An
   undeclared entry is `not_declared`; do not invent one. For an operator-supplied
   exact entry record, use `query: {"record_id":"EXACT_ID","revision":1}` with
   the supplied semantic revision. Never substitute the latest record. Exact
   outer object references instead use `query.object_ref` with kind, ID and
   outer revision; the checkpoint explains both forms.
5. Inspect pending work with
   `peerwork context operations PROFILE ACTOR SERVICE workspace.json` and use
   `peerwork context inspect PROFILE ACTOR SERVICE workspace.json` for verified
   state. Reconcile uncertain work using
   `peerwork context recover PROFILE ACTOR SERVICE recover.json`, containing
   exactly one original `operation_id` or `command_id`. Do not submit a
   replacement intent. Older unguarded rows may require the original command ID
   from pending work; there is no association backfill.
6. For a new authorized action, run
   `peerwork operate PROFILE ACTOR SERVICE action.json`. Besides the common
   workspace/fingerprint fields, provide a stable `operation_id` and
   `intent: {"kind":"protocol.action","instance_id":"EXACT_INSTANCE",
   "action_id":"SELECTED_ACTION","values":{},"refs":[]}` with the actual
   selected schema values and exact refs. The SDK handles signing/encryption.
   Require verified acceptance and matching command-bound receipt/effects;
   `ok:true`, exit zero and a saved pending row alone do not prove completion.
7. For receipts, call `peerwork context event-sync PROFILE ACTOR SERVICE
   workspace.json`, then `peerwork context event-receive PROFILE ACTOR SERVICE
   receive.json`. The receive request additionally names `consumer_id`,
   `filter_version`, `lease_ms` and `wait_ms` (requested budget at most 60000 ms,
   cooperative cancellation). Inspect `value.result.delivery` and its structured
   `receipt`. Acknowledge accepted delivery with `peerwork context event-ack
   PROFILE ACTOR SERVICE ack.json`, carrying the same consumer/version and the
   returned `ack_token`. Acknowledgement is not protocol-task completion.
   If the lease expires, receive again and acknowledge only the new token.

When interrupted or a budget ends, save a protected handoff containing the
selected profile, actor/service/workspace, opening fingerprint, original operation
or command ID, observed evidence/status and named next operation. For event
waiting, retain the consumer/version and caller-selected lease/wait budgets.
Current continuations are descriptors, not executable requests: map their
operation to the CLI verb (`events.receive` → `context event-receive`) and copy
only the request fields; do not put `operation` inside request JSON. Resume the
same work within a new explicit budget. Do not publish private receipt content,
lease tokens, signing keys or protected state in the handoff.

Native PRIVATE browser approval is a separate authorized intent:
`{"kind":"browser.approve","reference":"EXACT_BROWSER_REFERENCE","approve_writes":false}`.
Preserve the exact reference and explicit write-consent choice. Verified
`value.result.approval_code` is sensitive: deliver it privately to the intended
browser, never publish it or log command output. `browser_consumption: "pending"`
is distinct from verified approval; it does not prove redemption or browser use.
Recover uncertainty by the original saved ID. This producer requires no source
checkout or TypeScript helper and does not grant member rights.

Events currently cover verified action receipts only. Unchanged initialized
sources use a signed checkpoint probe; updates still require full-history replay
(`incremental: false`). A consumer version is a label, not a filter engine.
Admission-browser approval, new-member cold start, broader event sources,
executable continuation resume, all-platform qualification and new public release
availability remain separate work. Existing specialized clients remain supported.

T283 passed core/runtime checks, installed browser-protocol redemption/decryption
and Python/Node/CLI recovery parity. T284 passed 24 native checks and installed
discovery/probe acceptance. One natural-Agent trial passed business correctness
and workflow after a retained model-capacity interruption and stale-lease recovery;
it was not an uninterrupted first-attempt workflow pass. These are scoped local
synthetic-service results, not current-PROD or public-release qualification.
