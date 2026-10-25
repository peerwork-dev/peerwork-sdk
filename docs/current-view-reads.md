# Current reads and workspace navigation — unreleased candidate

The current candidate supports only `backend-structure-v1`. It is not a
production availability announcement or published SDK version. Earlier
`CurrentPageClient`, `PublicReadViewClient`, secure-journal and journal-replaying
Changelog examples do not describe this contract. Their online paths are
retired; an SDK upgrade never enables an implicit legacy fallback.

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
official source. Candidate `read`/`read_async` use indexed newest-first pages,
with `cursor` and a new-profile `checkpoint`; no offsets, full-history replay or
total-count scan. Node/Python/CLI reading,64KiB public bodies, forged-content
refusal and changed-cursor diagnostics have local installed-package qualification.
The production official workspace still needs conversion and publication. This
is not an announcement of deployed endpoints or published packages.

See the [PUBLIC reader examples](backend-structure-publication-candidate.md).
