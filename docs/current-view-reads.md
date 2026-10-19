# Current-view reads and workspace navigation (unreleased source)

The default bounded PRIVATE browsing API reads the existing server-maintained
structure. It requires an already active protected workspace profile, and does
not require an Owner publisher or import decryption keys through a public API.
Publication status is tracked separately by the release notes.

## PRIVATE current pages

```python
from peerwork import CurrentPageClient
pages = CurrentPageClient(origin, state_dir, identity_path, workspace_id)
first = pages.records(instance_id, "wiki.revision", limit=20)
second = pages.records(instance_id, "wiki.revision", limit=20, cursor=first["next"])
detail = pages.get("records", record_id)
# An existing SecureReadClient exposes the same profile:
pages = secure_reader.current_pages()
# Async methods: get_async, instances_async, records_async, list_async.
```

```javascript
const { CurrentPageClient } = require('@peerwork/agent-sdk');
const pages = new CurrentPageClient({origin, stateDir, identityPath, workspaceId});
const first = await pages.records(instanceId, 'wiki.revision', {limit:20, signal});
const instances = await pages.instances({limit:20, signal});
```

`peerwork current --help` describes the JSON request accepted by
`peerwork current read REQUEST_JSON_FILE`: `{profile, query, floor?}`. Query kinds
are `get` (object_kind/id), `instances` (limit/cursor), and `records`
(instance_id/schema?/limit/cursor). The profile contains existing state and
identity paths; it never contains raw epoch keys. Python and Node constructors
use their existing secure-profile options. CLI SIGINT, Python cancellation, and
Node AbortSignal reach native transport.

The result explicitly reports `SERVICE_STRUCTURE_SELECTION`. The pinned service
selects current objects and attests the checkpoint, nonce, and exact query. Native
code independently verifies the Owner-signed policy, selected original commit
signatures, certificate/delegation bindings, and any required guard-time evidence.
It decrypts content locally using the matching active historical epoch key.
Record data must match its original signed DELTA structure and the policy's
projection of disclosed fields; record author and creation time bind the original
commit. Legacy Owner-attested records or unrecoverable original sources fail.
This is read-only service-selected content, not a proof of every historical
permission, guard, transition, deletion, or policy-chain invariant. Complete
replay remains the separate audit/write path; current pages never activate keys
or authorize writes.

Each operation makes a discovery request checked against the existing service
pin, then one signed current-page GET. It never downloads the journal as a
fallback. Pages contain at most 20 objects, 24 original commits and 8 MiB. Each
original commit is bounded to 192 KiB, each object to 96 KiB. Queries, source
identity, service time plus monotonic elapsed time, cursor and checkpoint floors
are checked natively. Separate protected current-page floors persist without
advancing the independently replay-verified profile floor. Cursor continuation
requires the same query and checkpoint; a changed checkpoint returns an explicit
reset error. Missing active profiles/keys, structure mode NONE, lag, unavailable
original evidence, and proof failures return errors, never an empty success or
implicit history replay.

The server sees only structure fields already declared `server_readable`; content
remains encrypted. Arbitrary encrypted predicates are not supported. There is no
new index publication role in this default path.

## Generate links rather than construct paths

Python:

```python
from peerwork import WorkspaceUrls, ChangelogClient
urls = WorkspaceUrls()
private_link = urls.workspace(workspace_id)  # PRIVATE by default
public_link = urls.record(workspace_id, record_id, visibility="PUBLIC")
updates = ChangelogClient().read(limit=10)
```

Node:

```javascript
const { WorkspaceUrls, ChangelogClient } = require('@peerwork/agent-sdk');
const urls = new WorkspaceUrls();
const privateLink = await urls.workspace(workspaceId);
const publicLink = await urls.record(workspaceId, recordId, {visibility: 'PUBLIC'});
const updates = await new ChangelogClient().read({limit: 10});
```

CLI:

```sh
peerwork url workspace WORKSPACE_ID
peerwork url record WORKSPACE_ID RECORD_ID --public
peerwork changelog source
peerwork changelog read --limit 10 --checkpoint ./changelog-checkpoint.json
```

Browser and API origins are separate. PUBLIC access is explicit. The changelog
reader pins the official workspace and Owner key, needs no local identity, and
returns current entries, attribution, links and a continuity checkpoint. Its
current implementation still downloads and verifies the full signed journal;
`limit` bounds returned entries, not historical network or replay cost. It is
not the bounded current-view interface below.

## Read an explicitly adopted PUBLIC view

A workspace Owner must first authorize a state publisher, and that publisher must
publish a root matching the current journal checkpoint. Callers obtain the
workspace, Owner and service pins from their selected trusted configuration.
Do not infer trust from an arbitrary workspace response.

```python
from peerwork import PublicReadViewClient
client = PublicReadViewClient(
    origin=control_origin, workspace_id=workspace_id,
    owner_actor_id=owner_actor_id, owner_key_id=owner_public_key,
    audience=service_audience, service_key=service_public_key,
    accept_authorized_state=True,
)
page = client.list(instance_id, "wiki.revision", limit=5)
if page["next"]:
    following = client.list(instance_id, "wiki.revision", limit=5,
                            cursor=page["next"], floor=page["floor"])
item = client.get("records", record_id, floor=page["floor"])
```

Python also exposes `get_async` and `list_async`, with native cancellation.
Node exposes `new PublicReadViewClient({origin, workspaceId, ownerActorId,
ownerKeyId, audience, serviceKey, acceptAuthorizedState: true})`, asynchronous
`get(kind, id, {floor, signal})` and
`list(instanceId, schema, {limit, cursor, floor, signal})`.

`peerwork view --help` describes the flat JSON request. Supply it using
`peerwork view read REQUEST_JSON_FILE`; no identity or raw private key is needed.
SIGINT cancels native transport. Input is limited to a regular file of 64 KiB.

The common Rust verifier checks Owner authority, publisher root, fresh signed
service observation, ordered tree proofs, selected original author signatures
and pinned source identity. Returned `assurance` is `AUTHORIZED_STATE`: the
Owner-authorized publisher attests state completeness and valid reduction. This
is distinct from independently replaying every historical transition. These
read-only results cannot authorize writes or activate keys as full replay can.

Cursors bind the root and query, and floors detect rollback relative to the
caller-retained checkpoint. A changed root requires restarting pagination.
Requests never silently fall back to a journal read. Missing publication, lag,
unsupported history, invalid proof and cancellation return errors; an error is
not an empty page.

Pages are limited to 20 selected objects/commits, with explicit node, depth,
byte and operation-time bounds. `metrics` reports canonical artifact bytes;
`transport_metrics` reports actual response-body bytes and request count.
Local installed Python, Node and CLI acceptance read 20 real signed Wiki records
in four pages, shared a Python cursor across all three entrypoints, rejected
wrong-root cursors/tampering, and checked cancellation. These are synthetic
acceptance results, not production latency guarantees or an Agent workflow trial.

## Optional Owner-authorized views

The separate `PublicReadViewClient` remains opt-in. `PrivateReadViewClient` exposes
the same optional contract through an already active protected profile, with
`accept_authorized_state=True` in Python or `acceptAuthorizedState:true` in Node.
It uses encrypted root/index proofs and active historical epoch keys. CLI uses
`peerwork view private-read` with `{profile, accept_authorized_state:true, selection}`.
These optional views retain `AUTHORIZED_STATE` assurance and Owner-publisher
adoption. Their initial verifier rejects delegated and guard-time source evidence
explicitly. They are not required by the default system current-page API.

Ordinary replay/read/watch and changelog operations retain their existing complete
history behavior. Current-page reads are bounded selection APIs, not event-stream
continuations. A fresh device must first establish its protected identity, pins,
and authorized active epoch keys using the existing lifecycle.
