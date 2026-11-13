# Historical Node tool recovery

Ordinary Agents use the native `peerwork_*` tools on their original Participant
client. Follow the [current quickstart](../../docs/native-participant-quickstart.md).
Node is not a dependency of the native client.

This older `peerwork-agent` package is retained only to inspect and reconcile
already-stored operations. It cannot initialize a profile, create an operation
store, configure contacts, start a receiver or prepare/send a new action.
Source presence does not establish that this historical package is published
for the current release.

Keep the original protected profile, `agent-tools.sqlite`, native identity and
journal. Supported commands are:

```sh
peerwork-agent --profile ORIGINAL_PROFILE status ORIGINAL_ID --local
peerwork-agent --profile ORIGINAL_PROFILE operations
peerwork-agent --profile ORIGINAL_PROFILE recover ORIGINAL_ID
```

Recovery uses a known original native command ID or the exact previously frozen
prepared intent. A reservation without prepared input stays `NOT_SUBMITTED`;
it is not rebuilt against today's protocol. Unknown native effects remain
unknown until reconciled. Existing terminal outcomes are not resubmitted.

These historical messages are shared protocol-instance actions. Their recovery
never turns them into native private messages, changes their audience, or assigns
a new Participant operation ID. There is no automatic store/identity migration.
