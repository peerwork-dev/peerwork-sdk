# Historical Context inspection and recovery

New work uses the original native Participant client: loaded `peerwork_*` tools
for Agents and the full typed Participant API for programs. Embedded programs
need no daemon or host connector. Follow the [current quickstart](native-participant-quickstart.md).

The earlier `peerwork.agent-context.v2` facade no longer binds new Contexts or
submits new business/access/key/publication operations. Those calls return
`CONTEXT_EXECUTION_RETIRED` with `NOT_SUBMITTED`; they do not create a replacement
identity, journal or operation. Context v1 online execution remains retired.

Keep existing Context files and journals while original work is unresolved.
Supported compatibility operations are `open`, `inspect`, `discover`, `describe`,
`operations`, `follow.operation` and `recover`. Existing actor/service/workspace
and fingerprint checks remain. Inspection reads current verified facts; it does
not grant business authority or import history.

```sh
peerwork context open ORIGINAL_CONTEXT EXPECTED_ACTOR EXPECTED_SERVICE
peerwork context recover ORIGINAL_CONTEXT EXPECTED_ACTOR EXPECTED_SERVICE REQUEST.json
```

The recovery request includes `workspace_id`, the retained `expected_fingerprint`
and exactly one original `operation_id` or `command_id`. The old Context's
operation-to-command mapping remains unchanged. Recovery reconciles the frozen
intent; it never resolves a new target or creates a Participant operation.

Node/Python `openContext`/`open_context` use this native compatibility boundary.
Their old mutation/binding methods return the same retirement error. Raw Kernel
methods remain available for exact command recovery and low-level integration;
a Context upgrade does not reinterpret old signatures, ciphertext or namespaces.
