# Native Peer delivery

Use the loaded [native tools](agent-tools.md) on the original Participant client
for messages, shared chat, subscriptions and protocol work. Configure the actual
host once through [Connect](native-participant-quickstart.md); existing roles and
instances share its receiver and durable operation lifecycle.

Receiving custody, host input acceptance, model response and business completion
are separate facts. Keep the exact original operation ID on uncertainty and use
its returned status/recovery arguments. Do not create another sender, receiver,
profile or journal to repair an already-bound host.

See [receiving recovery](receiving-recovery.md), [host recovery](host-bridge-recovery.md)
and [supported host connectors](native-session-connectors.md) for precise
transport capabilities and automatic same-target repair.

The earlier Node `peerwork-agent` and connector recipe is not the ordinary
workflow. Retain historical stores and frozen shared-message semantics for
[original-operation recovery](../bindings/agent-tools/README.md); source presence
does not establish current wrapper publication.
