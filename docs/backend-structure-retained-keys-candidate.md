# Retained-history key delivery

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

## One Owner operation

The default approval grants the current key only. An Owner can explicitly include
published historical key epochs using the same approval operation:

```javascript
const approved = await owner.authorizeAccess(workspaceId, {
  request_jws: request.result.request_jws,
  include_history: true,
});
// approved.status describes the original signed access approval.
// approved.key_history separately reports READY, PENDING or UNAVAILABLE.
```

```python
approved = await owner.authorize_access_async(workspace_id, {
    "request_jws": request["result"]["request_jws"],
    "include_history": True,
})
```

The advanced Kernel clients accept the same option with `workspace_id` in the
selection. CLI `kernel access-approve` accepts that JSON selection as well.
Node, Python and CLI share the native implementation; no binding implements its
own key enumeration, encryption, replay or recovery loop.

The SDK signs `retained_key_epoch_ceiling` using the authenticated current epoch
observed during preparation. The service verifies the ceiling does not exceed
its current head. An advanced signed protocol command may select a smaller
positive ceiling. The policy binds the original Owner authorization, workspace,
actor, membership generation, certified recipient and expiry. It neither grants
a business action nor changes the default `follow_current_key: false` setting.
Future current keys require separate explicit consent.

The access approval atomically creates its backend delivery job. The SDK attempts
that selected job within the original shared call budget. The immutable approval
receipt can still contain `retained_key_job.state: PENDING` after work completes;
`key_history` is a separate, fresh readiness observation. It never rewrites that
receipt or claims that business acceptance alone proves all bodies are readable.

## Backend cursor and native crypto

The service selects at most32 old published epochs per page using
`(workspace_id,epoch)`. It excludes keys already delivered by the initial approval,
keeps a persistent job cursor and admits proof bytes before fetching signatures.
There is no journal replay, offset scan, recipient inventory scan or synchronous
full-workspace reconstruction in this operation.

The Owner native worker verifies the original Owner policy and every selected
epoch's Owner signature before loading its local secret. Scope-typed core values
bind Owner, workspace, audience and authorization digest; verified epochs cannot
be mixed across policies or workspaces. One HPKE envelope holds at most32 keys
under the distinct `peerwork.retained-body-keys.v1` context. Its selected recipient,
job, membership, expiry, ceiling and exact epoch/key list are authenticated.

The service receives commitments, routing metadata and ciphertext. It receives no
body keys or plaintext bodies. Its delivery transaction checks the current
membership generation, expiry, page token and job revision. A membership or
certificate that ended closes the job without granting additional keys.

The original admission CSR is evidence of the original accepted authorization.
It is not submitted again, consumed again or used to create another membership.
Processing can continue after its ten-minute request window, while the approved
membership, certificate and historical policy remain valid.

## Waiting and recovery

A readiness result has `job_id`, `through_epoch`, `state` and an optional diagnostic
`code`. A pending job can continue in the native Owner client runtime:

```sh
# worker.json: {"workspace_id":"WORKSPACE_ID"}
peerwork kernel coordinate-content-keys "$ORIGIN" "$JOURNAL" "$IDENTITY" worker.json --watch
```

The process handles current-key and historical jobs. Its local selected stage
stores the original packet ID before a remote submission. After a disconnect or
process exit, it reconciles that packet before moving to another page. It also
reconciles a saved final batch when the backend job is already complete and is no
longer in the pending queue. A completed backend cursor alone does not establish
that an unverified local packet has a known outcome.

Backend pending jobs and local stages are separate indexed locators. A bounded,
persisted worker cursor lets other jobs progress when one job needs attention.
Missing Owner key material does not authorize skipping an epoch or inventing a
new key: readiness remains pending with `OWNER_HISTORY_KEY_MISSING`. Restore the
corresponding protected Owner key cache, then continue the same job. Signing seed
backup alone cannot reconstruct previously generated random body keys. Keep the
Owner identity, native key cache, intent journal and selected configuration
available to the Owner runtime.

Native selected body reads and the browser request only missing keys needed for
the selected records. They verify the supplying Owner signatures and HPKE context,
then retain exact historical material without replacing a newer current-key
selection. Browser keys remain non-extractable in IndexedDB. A new range policy
or membership renewal requires explicit new Owner authorization; history delivery
does not implicitly renew or broaden it.

## Protocol entry points

| Action | Authority | Bounded work |
| --- | --- | --- |
| `structure.access.authorize` with a retained ceiling | Owner | Original approval plus one delivery job |
| `structure.content-key.history.jobs.read` | Owner | Live keyset page, limit1–32 |
| `structure.content-key.history.get` | Owner | One job and up to32 epoch proofs |
| `structure.content-key.history.deliver` | Owner | One signed page, at most32 encrypted keys |
| `structure.content-keys.read` | Current authorized recipient | Existing selected-ID reader, at most32 keys |

History ranges are limited to published epochs at or below the signed ceiling.
Later epochs are excluded even when processing resumes after another rotation.
Existing explicit selected-key grants remain available for separately selected
cached keys; the range worker does not enumerate unpublished local secrets.

Schema7-to8 is additive and explicit. It adds an empty job table and pending index,
preserving existing workspaces, keys, signed commands, receipts and publications.
The local key-cache upgrade also adds empty locator tables without replay or
identity migration. Admission, business submission, current-key publication and
recipient readiness retain separate meanings.
