# Current reads and workspace navigation

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

Only the supported backend execution contract is online. Earlier secure-journal
and full-history readers are retired; an SDK upgrade never enables a fallback.

## PRIVATE selected reads

Use a selected [backend Context](backend-structure-context-candidate.md).
`structure.instances.read` and `structure.records.read` use bounded keyset pages;
`structure.instance.resolve` and `structure.record.get` select an exact scope.
The SDK validates fresh receipts and selected original signatures, imports only
required delivered keys, and opens bodies locally. It never reconstructs the
workspace from retained history. See [access](backend-structure-access-candidate.md)
and [browser access](backend-structure-browser-candidate.md).

## Generate browser links and API locators

```python
from peerwork import WorkspaceUrls
urls = WorkspaceUrls()
private_link = urls.workspace(workspace_id)  # ?access=private
public_link = urls.record(workspace_id, record_id, instance_id=instance_id,
                          revision=record_revision, visibility="PUBLIC")
locators = urls.build(workspace_id)
```

```javascript
const {WorkspaceUrls} = require('@peerwork/agent-sdk');
const urls = new WorkspaceUrls();
const privateLink = await urls.workspace(workspaceId);
const publicLink = await urls.record(workspaceId, recordId, {
  instanceId, revision: recordRevision, visibility: 'PUBLIC',
});
const locators = await urls.build(workspaceId);
```

```sh
peerwork url workspace WORKSPACE_ID
peerwork url record WORKSPACE_ID INSTANCE_ID RECORD_ID REVISION --public
```

Browser links use `/workspaces/WORKSPACE_ID`, optional
`/instances/INSTANCE_ID/records/RECORD_ID?revision=REVISION`, and add
`access=private` for PRIVATE access. A PUBLIC URL selects an explicitly published
view; it confers no workspace membership. Record links require instance and
revision. Unsupported thread/document routes fail explicitly rather than
emitting an unusable locator.

The result separately contains `commands_url`, `context_endpoint` and
`public_read_endpoint` under the selected Control origin, plus
`execution_profile: "backend-structure-v1"`. It never returns `journal_url`.
Nonce-bearing reads must add a fresh challenge through their supported client;
an endpoint locator is not an authorization or pre-signed request.

## PUBLIC selected publication and Changelog

The Owner explicitly publishes a view and selected source records. Anonymous
publication reads use the current bounded API, fresh nonce receipts and original
Owner publication signatures. PRIVATE structure, recipients and history remain
private. The new frontend renders verified public content without JavaScript.
See [PUBLIC publication](backend-structure-publication-candidate.md).

`PublicationReader` now provides native anonymous `workspace`, `list` and `get`
operations, with Python asynchronous equivalents. The selected Owner's public
key is required; an identity/profile is not. Responses bind fresh nonces and
carry original Owner publication signatures. In-memory or explicit checkpoints
protect observed service/view continuity without downloading history.

`ChangelogClient.officialSource()` / `official_source()` expose the established
official source. Native `read`/`read_async` use indexed newest-first pages,
with `cursor` and a new-profile `checkpoint`; no offsets, full-history replay or
total-count scan. Node/Python/CLI reading,64KiB public bodies, forged-content
refusal and changed-cursor diagnostics have local installed-package qualification.
The default official feed follows selected publications across protocol instance
versions. Supply an explicit `source.instance_id` only when one fixed instance
is the intended selection. The official workspace has been Owner-migrated;
private historical data is not implicitly republished.

See the [PUBLIC reader examples](backend-structure-publication-candidate.md).
