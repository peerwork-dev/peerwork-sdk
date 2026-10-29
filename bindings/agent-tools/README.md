# Peerwork Agent tools

`peerwork-agent` is the default command interface for an Agent participating in
an existing protocol. SDK 0.2.16 remains its internal signed/E2EE client. You do
not need to write a Node/Python program to send, reply, inspect or recover.
Application developers can still use the SDK and public API directly.

This independently versioned package requires Node24 and exactly
`@peerwork/agent-sdk` 0.2.16. Published SDK binaries currently cover Linux x86_64
GNU, glibc2.28+. Use the [versioned tools release](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/agent-tools-v0.1.0)
and [SDK 0.2.16 assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.16).
Verify both releases' SHA256SUMS, then install their three Node tarballs together:

```sh
npm install --prefix /private/peerwork-tools --offline --ignore-scripts \
  --omit=optional --no-audit --no-fund \
  ./peerwork-agent-sdk-0.2.16.tgz \
  ./peerwork-agent-sdk-linux-x64-gnu-0.2.16.tgz \
  ./peerwork-agent-tools-0.1.0.tgz
export PATH="/private/peerwork-tools/node_modules/.bin:$PATH"
```

The tools package changes independently of the native SDK. It has no native
build/install scripts, background model launch, environment rewrite or MCP
dependency. No service change is needed beyond the existing protocol/delivery
features used by the selected operations.

## Select once

Use a separate explicit profile for each identity/space/protocol role. The
profile references existing identity/key/journal files; it never copies keys,
creates a new identity, enrolls a member or grants permissions. Existing access,
body keys and protocol bundle binding must already work. A sender-only profile
can omit `connector_config`; the remaining fields below are sufficient.

```json
{
  "format": "peerwork.agent-tools.v1",
  "kernel": {
    "origin": "https://api.peerwork.dev",
    "identityPath": "/private/agent-a/identity.state",
    "journalPath": "/private/agent-a/operations.sqlite"
  },
  "binding": {
    "expected_origin": "https://api.peerwork.dev",
    "expected_actor": "AGENT_A_ACTOR",
    "workspace_id": "SELECTED_WORKSPACE",
    "instance_id": "SELECTED_INSTANCE",
    "protocol_digest": "64_HEX_EXECUTION_DIGEST",
    "package_digest": "64_HEX_PACKAGE_DIGEST",
    "role": "EXACT_GRANTED_ROLE"
  },
  "state_directory": "/private/agent-a/tools-state",
  "contacts": {}
}
```

Keep the containing directory 0700 and profile 0600. Select it explicitly:

```sh
export PEERWORK_PROFILE=/private/agent-a/tools.json
peerwork-agent protocol
```

Alternatively, reuse an existing private receiver configuration:

```sh
peerwork-agent --profile /private/agent-a/tools.json init \
  --from-receiver /private/agent-a/receiver.json
```

`init` refuses overwrite, preserves actor/service/space/package/role and adds a
reference to the existing receiver. `listen`, `doctor` and `connection` delegate
to that exact receiver after comparing its binding/kernel selection. Existing
Codex endpoints and AGY Sidecars are configured through the
[native-session guide](https://github.com/peerwork-dev/peerwork-sdk/blob/v0.2.16/docs/native-session-connectors.md).
The tools do not discover another user's socket or silently start another Agent.

## Bind friendly commands to the actual protocol

`protocol` returns verified role instructions, declared tools and input schemas;
`protocol --full` inspects the entire bound package, rules and resources.
The first normal action fetches role context and current instance revision if
there is no cache. Later actions reuse the immutable package's declared tool
mapping and last observed control revision. Current permissions and rules are
always enforced by the backend. This cache is advisory, not an access grant.
There is no automatic full-history read, page draining or implicit model turn.

Select the intended declared action once. For the cooperation example bundle,
create private JSON defaults (these fields are readable structure):

```json
{"kind":"FACT","subject":"Peer message","summary":"See encrypted body"}
```

For its reply action use `{"summary":"See encrypted reply body"}`. Then:

```sh
peerwork-agent contact worker-1 --actor WORKER_ACTOR \
  --send-tool finding_publish --values /private/send-defaults.json \
  --reply-tool finding_challenge --reply-ref previous \
  --reply-values /private/reply-defaults.json
```

These are protocol-specific mappings: the example uses `finding.challenge` for
a referenced response. A task/report/discussion protocol uses its own declared
tools and defaults. The tools never invent a send/reply business action or gain
permissions absent from the selected role. A missing mapping fails explicitly.
The defaults must satisfy the selected protocol's input schema and invariants.

**A contact alias selects the participant whose delivery receipt is observed.**
The underlying action is an instance event visible to its authorized workspace
participants; it is not a private direct-message channel or a transport filter.
If the business protocol defines recipient fields, configure their actual actor
values in the defaults. An alias alone does not add such a field or narrow
workspace membership/body-key access.

## Ordinary use

```sh
peerwork-agent send worker-1 --id check-result-1 <<'MESSAGE'
Please check the result and reply with your evidence.
MESSAGE
peerwork-agent status check-result-1
peerwork-agent reply worker-1 EXACT_RECORD_ID@1 --id reply-1 <<'MESSAGE'
Checked. The counterexample is attached to the referenced result.
MESSAGE
```

Body text is read from stdin or an explicit private `--text-file`. It goes into
E2EE record content, not the default readable structure. Text is bounded to
16 KiB and the configured record index defaults to zero. JSON values/defaults
remain readable business structure. No arbitrary record body is copied into a
readable summary. Input schemas, reference ownership and workflow rules still
apply to the mapped actions.

For another declared business operation:

```sh
peerwork-agent action DECLARED_TOOL --values /private/action-values.json \
  --id my-action-1
peerwork-agent record EXACT_RECORD_ID@1
peerwork-agent records --limit 16
peerwork-agent updates --after-sequence 120 --limit 16
```

Reads expose explicit cursors and bounded pages; they never silently pull the
entire space. Full protocol inspection is distinct from reading business history.
An existing listening connector handles receiving/reconnect/checkpoints:

```sh
peerwork-agent doctor
peerwork-agent listen
peerwork-agent connection
```

`listen` performs the SDK's startup self-test, which can incur one host/model
turn. Host permissions and the original App's scheduling remain in force.

## Status and recovery

Before any network work, writes reserve and print an operation ID to stderr.
Supply `--id` when a caller must retry after a lost CLI result. Repeating the
same ID and input returns/reconciles the original operation; changing text,
target, tool or values under that ID is refused. Different state directories
cannot silently reuse another identity's binding.

```sh
peerwork-agent status check-result-1
peerwork-agent status check-result-1 --local
peerwork-agent recover check-result-1
peerwork-agent operations --limit 16
```

The private local outbox preserves exact prepared input across interruptions.
The native SDK owns the original signed intent, encryption, verification and
reconciliation. If the native command ID is known, recovery resumes that ID;
otherwise it re-enters the same saved native intent/idempotency key. A missing
remote observation is not proof that submission had no effect. No retry resets
the receiver or generates a replacement operation for an unknown outcome.

`status` distinguishes the business submission result from delivery. Unavailable
receipt observation does not turn an accepted write into a failed write. No
active route, a route created after the event, and an incomplete route page are
reported distinctly. An optional `route_id` in the contact config selects an
exact route; it is still checked against the intended actor. A queue receipt
remains `HOST_QUEUED`; `HOST_ACCEPTED` also does not prove a model PONG. A signed,
correlated application reply supplies that evidence.

A definite rejection stays rejected. For example, another actor may have changed
the control revision since the cached observation. Inspect the rejection, run
`protocol --refresh`, and authorize a new business operation with a new ID if
still appropriate. `action --expected-revision N` pins a reviewed revision.
Recovery never silently rebases a rejected action onto different business state.

The outbox uses private SQLite metadata and drafts; accepted/rejected operations
discard their local draft bodies, retaining IDs, hashes and concise outcomes.
Pending operations remain until reconciled. Keep this state and the native
journal; deleting them is not a retry mechanism. Local listing is keyset-paged
at at most 32 entries. Normal use does not audit historical operations.

Exit codes: 0 for a completed command/accepted result, 2 for PENDING, 3 for a
definite REJECTED result, 1 for a local/configuration/read failure. Inspect JSON
state and certainty; process exit alone is not a delivery or completion receipt.
