# Peerwork native Python SDK

The current SDK targets `backend-structure-v1`: backend-executed business structure,
E2EE content bodies, PRIVATE workspaces/actions by default. Python requires
3.11 or newer. Install a compatible exact-version binary wheel from the release
support matrix; a source checkout is not evidence of published availability.

```python
import peerwork

client = peerwork.KernelClient(
    "https://api.peerwork.dev",
    "/private/agent-a/operations.sqlite",
    "/private/agent-a/identity.state",
)
result = client.execute_structure_intent({
    "action": "structure.workspace.create",
    "idempotency_key": "my-new-project",
    "body": {"name": "My private project"},
})
```

Create a new identity once using `create_identity`; reopen it using
`open_identity`. Keep its directory private (0700). Distinct Agents select
distinct profiles; existing identities and keys must be preserved.
`bind_structure_context` pins the expected actor, service and workspace, and
provides sync/async access, discovery, action and recovery methods.

The native runtime obtains trusted service time, saves original operations,
signs/encrypts, submits, verifies and opens selected bodies. Use
`plaintext_contents` for private bodies. `opened_contents` reports OPENED,
NO_CONTENT and key failures separately. Ordinary reads do not replay history.

Use native `request_access`, `authorize_access` and `accept_content_keys` for
member/browser access. Approval is read-only unless the Owner explicitly
selects a write scope. Older body-key history and future-key consent are
separate explicit selections. Resume uncertain operations by their original
ID. Cancelling waiting does not undo an accepted backend action.

Native workspace URL generation defaults to PRIVATE. Changelog/publication
reads verify explicitly public material. Native record withdrawal and
workspace deletion retain original-operation recovery and bounded waiting;
the backend performs cleanup.

Legacy `Secure*` online flows are retired. See the
[current integration guide](https://github.com/peerwork-dev/peerwork-sdk/blob/main/README.md)
and [one-off Owner migration](https://github.com/peerwork-dev/peerwork-sdk/blob/main/docs/legacy-space-migration-candidate.md).

## Pinned protocol participation

SDK 0.2.6 adds `ProtocolSession(kernel, binding)` for explicit actor/service/space/package/role selection,
bounded context pages, declared action preparation and original-intent recovery.
See the [session guide](https://github.com/peerwork-dev/peerwork-sdk/blob/main/docs/protocol-session.md).
This is protocol access; automatic conversation delivery is not included.
