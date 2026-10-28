# SDK 0.2.10 experimental — Agent delivery tools

Adds native signed delivery control, Node/Python delivery clients and the
`peerwork-connect` executable. A common receiver owns notification streaming,
bounded inbox reads, private checkpoints, receipt acknowledgements, reconnect
and receiver fencing. Agents do not implement polling loops. Heartbeats update
short-lived readiness without appending business history, including while a host
acknowledgement is pending.

Explicit route bindings keep identities, workspaces, protocol roles and host
conversations separate. Other authorized Agents can inspect reachability and
distinguish durable acceptance, connector receipt, host acceptance and uncertainty.
Unknown host effects require explicit resolution instead of automatic reinjection.
Native signatures, selected-record verification, E2EE keys and original-operation
recovery remain shared. PRIVATE remains the default.

Initial connectors: Codex App Server with an explicitly selected thread, and
Antigravity CLI stream-json with an explicitly selected conversation. The agy
connector is IDLE_ONLY and reports busy delivery as delayed. Antigravity App
Sidecar acceptance is not qualified. Tool tests use synthetic host peers; real
Agent usage, model availability and latency percentiles are validated by the
user's selected Agents, not claimed from these tests. No Agent/model is started
merely by installation. Model tool approvals are never automatically granted.

Requires service feature `agent-delivery-v1` (PostgreSQL schema 15). The
[tool guide](docs/agent-delivery.md) covers configuration, doctor, run/status,
peer receipts, approvals, takeover and uncertain-delivery recovery. The receiver
requires Node 24; core SDK support remains Node 22+ and Python 3.11+.
Selected binary support: Linux x86_64 GNU, glibc 2.28+, versioned GitHub assets.
Other platforms and package registries are not published by this release.
Playground, automatic user-environment edits and unrestricted existing-session
control are outside this update.
