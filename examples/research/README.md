# Research reference demos

Two small, runnable adaptations compose the [shared meta protocols](../meta-protocols/README.md):
[DeLM](delm/README.md) shares intermediate findings and produces a candidate per
peer; [Agensh](agensh/README.md) adds independently reviewed integration into a
shared Git repository. Both run two equal workers without a central task
assigner. The launcher creates workers and waits for their results.

These are protocol mechanism demonstrations. Their default workers are scripted,
the task is synthetic, and they do not measure model quality or reproduce the
papers' benchmark scores. See [credits and exact references](CREDITS.md).

## Offline: Node 24, no service or SDK installation

From a checkout of this repository:

```sh
node examples/research/delm/run.mjs --offline
node examples/research/agensh/run.mjs --offline
```

Both should report `status: PASS`, `total: 17`, `simulated: true` and
`model_quality_measured: false`. The local fixture invokes the actual Backend
compiler/evaluator exported into `vendor/backend-evaluator.mjs`. Its source
commit, input hashes, bundle hash and dependency licenses are retained beside
it. This is an executable state-transition check, not a replacement database,
transport, signature verifier, encryption system or authoritative service.

## Live: installed SDK 0.2.4+, Node 24, Git for Agensh

Install the exact Node package using the
[SDK 0.2.4 release instructions](../../RELEASE_NOTES_0.2.4.md), and ensure
`require('@peerwork/agent-sdk')` resolves from the working directory. Use a
service advertising `backend-structure-v1`. The demos add no server extension
and do not require a new native SDK binary.

Create a protected setup file and a fresh private directory for each experiment:

```sh
umask 077
mkdir -p .research-runs/delm
printf '%s\n' '{"origin":"https://api.peerwork.dev"}' > .research-runs/delm-config.json
node examples/research/setup.mjs .research-runs/delm-config.json .research-runs/delm
node examples/research/delm/run.mjs --binding .research-runs/delm/binding.json
```

This **explicit setup command writes to the service**: it creates a PRIVATE
workspace, two distinct worker identities/memberships, a findings board, two
work instances and selected action grants. Ordinary worker execution does not
administer the workspace. Keep the private directory, identities and native
operation journals to resume. Do not commit it or share its files in an issue.

For Agensh, use another fresh directory, then run its entry point:

```sh
mkdir -p .research-runs/agensh
node examples/research/setup.mjs .research-runs/delm-config.json .research-runs/agensh
node examples/research/agensh/run.mjs --binding .research-runs/agensh/binding.json
```

Agensh initializes a private bare repository and one checkout per peer. Two
small JSON artifacts are committed after independent review. Git integration
and backend adoption are separate effects: interrupted integration is reconciled
from its existing artifact/references before adoption. No atomic transaction
across Git and Peerwork, or exactly-once arbitrary shell execution, is claimed.

A successful live run reports two independent processes and two candidates
with total 17. Repeating the **same binding** reads the completed work and does
not submit it again. Use a fresh setup directory for a new experiment or a
different recipe. This example deliberately caps the board at 16 current
findings and uses two selected work instances, rather than inventing an
unbounded scheduler. Larger applications need their own bounded work discovery.

To use an existing Owner and workspace, explicitly set:

```json
{
  "origin": "https://api.peerwork.dev",
  "workspace_id": "SELECTED_WORKSPACE_ID",
  "owner": {
    "identityPath": "/private/owner/identity.state",
    "journalPath": "/private/demo-owner/operations.sqlite",
    "expectedActor": "EXPECTED_OWNER_ACTOR_ID"
  }
}
```

Setup pins that actor, persists selected immutable setup operations and grants
only the new instances. It requires Owner authority and the existing identity's
body keys. Do not point it at another Agent's active operation journal.

## Optional model/harness adapter

Add `"agentCommand": ["/absolute/path/to/harness-wrapper"]` to setup configuration.
The wrapper receives one JSON line on stdin with `goal`, `task`, `peer_findings`
and `recipe`, and returns one JSON object `{"text":"..."}` on stdout. For this
synthetic evaluator, `text` must be JSON containing exactly `task_id` and `value`,
where `value` is the sum of `task.numbers`. No shell string interpolation is used.
The default deadline is 60 seconds and output limit is 64 KiB; stderr is not
published. The wrapper is trusted local code under the same OS account, not an
OS sandbox. Native credentials are not supplied as request fields.

Artifacts are persisted once before submission, so request recovery does not
ask the model to generate a different replacement. Integrating a real benchmark
also requires its evaluator, task/repository adapter, prompts and budget/cost
records. A model wrapper alone does not make this a benchmark reproduction.

## Delivery, recovery and data limits

The shared example host owns bounded signed event polling, local delivery leases,
atomic enqueue/checkpoint and cancellation/backoff. Workers do not write their
own notification listener. This JavaScript adapter is example source using
Node's SQLite; it is not a new native SDK consumer API.

A store is bound to origin, authority, actor, workspace, selected instances,
recipe and filter version. Workers use separate identities/journals. Event pages
are at most 32; the queue refuses advancement at 1,024 events or 8 MiB. Default
subscription starts NOW; explicit saved positions continue bounded cursor pages.
The demo treats notifications as wakeups and re-reads the two selected current
states. For event-driven mutations, the generic dispatcher requires a durable
decision before acknowledgment. Delivery is at least once, with fencing against
stale acknowledgments.

Mutation decisions are persisted before submission. Unknown outcomes resume the
same native command; no replacement mutation is generated. Changed payloads
under the same decision key are refused. Intent metadata contains protected body
artifact paths/hashes, not body plaintext; artifacts and local Git checkouts are
private plaintext on the Agent host. Transport bodies remain E2EE. A granted
peer decrypts only the selected shared records it needs. Structural labels,
authors, references and statuses are service-readable.

Queue/decision exhaustion, changed identity/binding/artifact, unavailable body,
Git conflict or a non-retryable outcome requires explicit repair. A deadline
stops local waiting and does not undo accepted work. After resolving the cause,
rerun the same binding. Do not delete journals to retry an uncertain operation.
The examples use indexed state/record/event APIs and never request the journal.

## Maintainer acceptance

```sh
node --test --test-isolation=none tests/research/protocols.test.mjs tests/research/host.test.mjs
```

The optional real HTTP test requires the current Backend checkout compiled via
its `build:workspace` script, an isolated PostgreSQL test database, and the
installed SDK package path:

```sh
PEERWORK_RESEARCH_BACKEND=/path/to/backend \
PEERWORK_POSTGRES_TEST_URL=postgresql://testuser@127.0.0.1/testdb \
PEERWORK_RESEARCH_SDK=/path/to/node_modules/@peerwork/agent-sdk \
node --test --test-isolation=none tests/research/http.test.mjs
```

It creates/drops an isolated schema, runs both recipes through real HTTP and
separate SDK processes, loses one committed reply, resumes completed bindings,
checks Git results, concurrent claim exclusivity and expired-holder fencing,
and counts journal requests. It must not target a production
schema. Re-export the offline evaluator after Backend changes with
`node tools/research/export-backend.mjs /path/to/backend`; compiler semantics
must remain shared, rather than being reimplemented in the fixture.
