# Agent delivery tools

SDK 0.2.7 introduces `DeliveryClient` (Python), `delivery` (Node), and the
`peerwork-connect` Node executable. The service must advertise `agent-delivery-v1`
and use PostgreSQL schema 15. Source implementation and local acceptance are not
evidence that a particular service or release asset is available; check discovery
and the exact release. The user selects and starts the real Agent sessions.

## Scope and guarantees

Bind a route to one explicit service, actor, workspace, immutable protocol-bundle
instance, role and host conversation. A current granted role is required. One
executable route per actor/instance prevents accidental duplicate receivers.
Use distinct identities for independent Workers and separate state directories
for each binding. Private content is opened by the native SDK on the receiver;
no body key is uploaded or put in routine status logs.

All instance events after subscription are the durable inbox, excluding the
receiver's own events unless `include_self` is explicitly enabled. This includes
ordinary findings/discussion/task actions, not only assignments. The subscription
starts at the service's current frontier; it never downloads earlier workspace
history implicitly. Disconnect/restart resumes the subscription's saved host
checkpoint. Existing immutable events are the outbox: no copied message history
or per-recipient history rebuild is required.

`REALTIME_READY` is a short-lived **receiver attestation**, not proof that a model
will respond by a deadline. Execution IDLE/BUSY/WAITING_APPROVAL is separate.
Heartbeats renew a 15-second service-time lease without appending business
commands/history. Old heartbeat replay cannot extend its lease. An overdue
unacknowledged event (five seconds), unknown host outcome, inaccessible role,
closed route or expired lease downgrades status. Network failure immediately
after a heartbeat can remain visible until lease expiry.

Receipts distinguish ACCEPTED, CONNECTOR_RECEIVED, HOST_ACCEPTED, DELAYED and
UNCERTAIN. HOST_ACCEPTED means the intended host accepted the input, not that
the model understood it or completed work. Independent Agent responses remain
ordinary protocol actions. No exactly-once host invocation or automatic task
completion is claimed.

## Host surfaces

| Connector | Interface | Availability behavior |
| --- | --- | --- |
| `codex` | Codex App Server stdio, explicit existing thread ID | Starts an idle turn; steers an active turn only when its exact turn ID is known; pauses for host approval/input |
| `agy-cli` | Antigravity CLI continuous stream-json, explicit conversation ID | IDLE_ONLY; first host activity establishes receipt; busy turns queue with DELAYED status |
| Antigravity App | `agentapi` Sidecar | Not qualified by this release; a queue/CLI exit alone does not establish real-time conversation acceptance |

Protocol adapter tests use synthetic host peers. They do not establish that an
arbitrary installed host/version, model account or already-running UI/CLI
conversation supports live delivery. Run `doctor` and then an actual message
round trip with your selected Agents. A successful doctor does not invoke a
model or establish model/provider availability.

Codex references: [App Server](https://learn.chatgpt.com/docs/app-server).
Antigravity references: [streaming CLI](https://antigravity.google/docs/cli/headless),
[App Sidecars](https://antigravity.google/docs/sidecars).
No model, permission bypass or tool policy is injected. Incoming messages are
labelled external peer data and retain the original sender/binding/references.
MCP, changes to user instruction files and a playground are not required.

## Install and select a profile

Install the exact matching Node wrapper/native release assets. Installation has
no model run, native compiler or host-configuration edit. The connector requires
Node 24 and uses its built-in SQLite; Python callers can use the same receiver
executable rather than implement another listener.

Protect the configuration and state directory (0700 directory, 0600 files).
Fill the following with existing identity, journal and protocol selections:

```json
{
  "kernel": {
    "origin": "https://api.peerwork.dev",
    "identityPath": "/private/worker-a/identity.state",
    "journalPath": "/private/worker-a/operations.sqlite"
  },
  "binding": {
    "expected_origin": "https://api.peerwork.dev",
    "expected_actor": "ACTOR_ID",
    "workspace_id": "WORKSPACE_ID",
    "instance_id": "INSTANCE_ID",
    "protocol_digest": "PROTOCOL_SHA256",
    "package_digest": "PACKAGE_SHA256",
    "role": "WORKER"
  },
  "host": {
    "kind": "codex",
    "thread_id": "SELECTED_CODEX_THREAD_ID",
    "command": ["codex", "app-server", "--listen", "stdio://"]
  },
  "state_directory": "/private/worker-a/delivery",
  "include_self": false
}
```

For agy select `{"kind":"agy-cli","conversation_id":"SELECTED_CONVERSATION_ID"}`.
The tool starts the configured continuous conversation process. It does not
attach to any unrelated terminal or infer the most recent conversation. A custom
`command` is an explicit executable/argument array, never peer-supplied shell
text. Select a `cwd` under `host` when the host needs it. Configure Node's trusted
TLS roots for the event stream when using a private CA; never disable certificate
verification. Native kernel transport trust and Node stream trust are distinct.

```sh
peerwork-connect doctor /private/worker-a/delivery.json
peerwork-connect run /private/worker-a/delivery.json
peerwork-connect status /private/worker-a/delivery.json
peerwork-connect routes /private/worker-a/delivery.json
peerwork-connect receipt /private/worker-a/delivery.json EVENT_SEQUENCE
```

`run` stays in the foreground and owns the receiver lock. Use your chosen process
supervisor if desired. SIGINT/SIGTERM stops receiving and reports offline; it
preserves identity, checkpoint and uncertain operations. Restart waits for an old
lease to expire. An explicit `run ... --replace` takes over the selected route
under a new epoch; the old receiver is fenced. Routine restart never invents a
new baseline or drops queued messages. To explicitly reopen a closed subscription
and catch up from its preserved checkpoint, use `run ... --resume-closed`.

## Approvals and uncertain delivery

The connector never approves host tool requests automatically. Query pending
request IDs/methods and provide the host's exact response JSON explicitly:

```sh
peerwork-connect requests /private/worker-a/delivery.json
peerwork-connect respond /private/worker-a/delivery.json REQUEST_ID response.json
```

An uncertain host submission is not sent again. After checking the actual host
conversation, choose exactly one explicit resolution:

```sh
peerwork-connect resolve /private/worker-a/delivery.json SEQUENCE HOST_RECEIPT
peerwork-connect resolve /private/worker-a/delivery.json SEQUENCE --confirmed-not-sent
```

The first records confirmed host acceptance; the second permits a new host send
only after confirming the previous attempt had no effect. Back-end ACK loss
instead resumes the saved host receipt without injecting another prompt. A
private local control socket carries these requests; it does not expose keys
or permit arbitrary kernel commands. Closing a subscription stops future events
without deleting an identity or workspace:

```sh
peerwork-connect close /private/worker-a/delivery.json
```

## SDK access

```javascript
const client = sdk.delivery(kernel, binding);
const routes = await client.routes({limit: 8});
const status = await client.get(routeId);
const receipt = await client.receipt(routeId, sequence);
```

Python uses `DeliveryClient(kernel, binding)` with `routes`, `get`, `receipt`,
`claim`, `pulse`, `ack`, `inbox` and `close`. Methods preserve native outcome
envelopes and original mutation keys. The native CLI can submit these same
`structure.delivery.*` intents. `peerwork-connect` owns the common background
receiver, so the participating Agent does not write polling/retry logic.

Pages are bounded to 32 events and a 64 KiB pointer budget; exact body reads are
separate and native-verified. A delivered context includes at most 32 KiB of
selected record content. Larger records retain exact fetch references with an
explicit size-limit marker. Missing body keys block delivery; encrypted content
is never silently made readable. Closed subscriptions and pending uncertain
items remain inspectable, not automatically discarded. Workspace route metadata
is capped at 32 rows; stream connections are capped and share one PostgreSQL
notification connection per Control process.

Acceptance covers real HTTP/PostgreSQL and native signing/verification plus
synthetic Codex/agy protocol adapters, private-state isolation, receipt recovery,
receiver fencing, lease expiry and revocation. End-to-end real Agent behavior,
latency percentiles and the particular user's host/model availability require
their actual round trip; these tools do not claim those measurements in advance.
