# Local protocol tests with the native executable

The native executable exposes offline `compatibility`, `fixture`, `simulate` and
`plan`. These need no service, production identity, Node/Python installation or
product source checkout. Write a fixture and steps that express your business
rules; the native evaluator handles execution and diagnostics.

Historical online `export` and `apply` are retired. They do not become available
by installing a current SDK. The [archived0.1.9 guide](protocol-workbench-0.1.9.md)
describes old verified-history interfaces and must not be used as a current
online conversion workflow.

## Create and simulate a synthetic fixture

Save this business test input as `fixture-request.json`:

```json
{"schema":"peerwork.protocol-fixture.v1","protocols":[{"instance_id":"counter","manifest":{"name":"example.counter","display_version":"1","semantics":"peerwork.kernel.v1","dependencies":[],"record_schemas":{},"initial_state":{"count":0},"actions":[{"id":"set","reads":[["count"]],"writes":[["count"]],"revisionEffects":{"control":true,"contentEntities":[]},"variants":[{"when":[],"effects":[{"op":"set","path":["count"],"value":{"from":"literal","value":1}}]}]}]}}]}
```

```sh
peerwork protocol fixture fixture-request.json
```

The response contains `ok` and the fixture in `value`. Create a simulation input
using that returned fixture unchanged:

```json
{"schema":"peerwork.protocol-simulation.v1","fixture":"REPLACE_WITH_RETURNED_FIXTURE_OBJECT","steps":[{"instance_id":"counter","action_id":"set"}]}
```

```sh
peerwork protocol simulate simulation-request.json
```

Inspect `value.steps`, output state and diagnostics. Test actors/roles, invalid
references, revision conflicts, forbidden actions and lease-time boundaries as
appropriate. Synthetic time is a test input, never platform trusted-time evidence.
Simulation results are `authoritative: false` and carry no accepted service receipt.

The next release candidate also exposes the same offline evaluator through the
existing native MCP connection:

```json
{"mode":"request","operation":"protocol.offline","body":{"operation":"fixture","input":{"schema":"peerwork.protocol-fixture.v1","protocols":[]}}}
```

Call `peerwork_manage`; replace the empty protocols with the actual business
fixture above. The shared Participant helper returns its native result envelope;
use `result.value` as the fixture for a subsequent simulate request. It creates
no mutation intent and makes no HTTP request. No additional runtime is started.

## Versions and real business conversion

Protocol authoring, identity migration and business conversion remain separate.
New tickets can use a new instance while old tickets retain the old protocol.
If conversion is necessary, author the mapping, preserve exact source IDs and
revisions, and fence old claim authority before activating a replacement claim.
Several instance actions are not one global transaction.

Current record/protocol reads are bounded native `peerwork_read` and
`peerwork_protocol` operations. This release does not provide an automatic
backend-structure fixture export/online-plan application tool. Do not call a
retired journal reader or infer a complete fixture from one partial page.
Implement the explicitly selected current-profile business actions through the
original client; their normal permissions, CAS and same-operation recovery apply.
