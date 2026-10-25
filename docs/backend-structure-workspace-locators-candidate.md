# Short workspace URLs

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

## Generate a registered workspace link

Workspace creation and signed `structure.workspace.get` results contain
`workspace_alias`, a registered random16-character routing identifier. Use that
metadata rather than shortening, hashing or truncating the workspace ID:

```js
const observed = await kernel.executeStructureIntent({
  action: 'structure.workspace.get', workspace_id: workspaceId, body: {}
});
const urls = new WorkspaceUrls();
const privateUrl = await urls.workspace(workspaceId, {
  workspaceAlias: observed.result.structure.workspace_alias
}); // https://peerwork.dev/w/<alias>?access=private
```

Python uses `WorkspaceUrls().workspace(workspace_id,
workspace_alias=verified_alias)`. CLI:

```sh
peerwork url workspace WORKSPACE_ID --workspace-alias VERIFIED_ALIAS
```

These builders are offline and require no identity, network request or SDK
state migration. PRIVATE remains their default. An explicit `visibility: 'PUBLIC'`
(or CLI `--public`) omits the private-view query; it does not publish anything.
Instance/record links accept the same workspace alias while retaining exact
instance ID, record ID and revision. Canonical43-character workspace URLs remain
valid and use the same identity and browser session. An unknown alias never
falls back to interpreting it as a different ID.

`PublicationReader` and `ChangelogClient` automatically use the registered alias
returned in the service-verified PUBLIC view. Public catalog, no-JS reading and
PRIVATE browser navigation preserve short workspace paths. PRIVATE navigation
also preserves `access=private`, including record links and refreshes.

## Routing does not authorize access

`GET /api/workspace/v1/structure/locator?alias=ALIAS&nonce=RANDOM_43_CHAR_TOKEN`
returns only `{profile, alias, workspace_id}` and a service signature in the
`peerwork.workspace-locator.v1+jws` domain. The proof binds audience, profile,
nonce, query digest and result digest. The DBless frontend pins the service key
and verifies it before using the resolved ID. Its internal Control origin is
separate from the public browser origin and requires explicit identity pins.

A shared short link reveals its opaque workspace ID, just as a canonical link
contains that ID. This minimal routing mapping is intentionally public even for
a PRIVATE workspace. It contains no name, membership, protocol, record, body,
key or authorization. There is no alias listing endpoint. The indexed lookup is
subject to the existing public-read abuse limit and response-size bounds.
All workspace data reads, browser approval, content keys and business writes
still require their existing signed authorization. A short link is not an
invitation, grant or bearer secret.

Workspace creation allocates the alias transactionally. Explicit offline
conversion preserves the selected existing alias or creates missing routing
metadata; archive import fills missing aliases in committed batches of at most32
workspaces. Neither ordinary actions nor URL builders scan historical data.
No new table or schema migration is introduced; PostgreSQL schema remains11.

Deletion admission closes locator reads immediately. Physical cleanup retains
only a target-free alias tombstone, so a retired short address is never assigned
to another workspace. Unknown, unavailable and retired targets return404.

## Qualification and availability

Local acceptance covers92 PostgreSQL tests, actual installed Node/Python/CLI
builders and metadata reads, native PUBLIC/Changelog short links, selected
service-proof substitution refusal, and Chromium mobile/no-JS/private approval,
short navigation, reload and shared canonical/short identity. No acceptance
journey fetched a workspace journal. Instance and record IDs themselves remain
full identifiers; this change shortens the workspace portion of those links.
Exact supported service and SDK release versions will accompany publication;
development0.1.11 packages must not replace published0.1.11.
