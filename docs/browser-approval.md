# Authorize a workspace browser with the native SDK

Availability: the new Agent-context producer is prepared for the 0.1.2 experimental
candidate. Older published 0.1.1 experimental artifacts do not contain it. Use
an artifact that actually exports `open_context`/`openContext`/`context operate`.
This page describes workspace-browser approval; admission-browser approval is
not implemented by this producer.

The operator supplies an existing admitted member context, its expected actor
and service, and the exact PRIVATE workspace. The browser supplies the complete
`peerwork-browser-approval:v1:…` reference from its first step. Check the intended
workspace/browser and requested scope before approving. Create one unique logical
operation ID for this browser request; retain the same ID after interruption.
A new request needs a new ID. Do not copy keys, search source checkouts, enroll a
replacement identity or assemble a signed packet.

```python
import peerwork

ctx = peerwork.open_context(
    profile=CONTEXT_PROFILE,
    expected_actor=ACTOR_ID,
    expected_service=SERVICE_ID,
)
result = ctx.operate(
    WORKSPACE_ID,
    {
        "kind": "browser.approve",
        "reference": BROWSER_REFERENCE,
        "approve_writes": False,
    },
    operation_id=APPROVAL_OPERATION_ID,
)
if result["status"] == "verified":
    approval_code = result["result"]["approval_code"]
    # Deliver privately to the intended browser; paste into its second step.
```

`False` requests read-only consent. Use `True` only when browser writes are
explicitly authorized; approval cannot create membership or grants beyond the
selected identity's authority. The native producer verifies the exact request,
service/audience, device, workspace, scopes and expiry, then creates the signed
delegation and encrypted key delivery. A code is exposed only after its exact
command-bound receipt is verified. Do not print/store it in public logs.

If submission is pending or the reply was lost, reopen the same context and
recover the original logical operation:

```python
result = ctx.recover(WORKSPACE_ID, operation_id=APPROVAL_OPERATION_ID)
```

Do not create a replacement approval to hide an uncertain result. Expired
unresolved operations are not silently re-signed. A verified approval has
`browser_consumption: "pending"` until the intended browser redeems the code;
SDK acceptance alone does not prove that the browser has opened the workspace.

Node uses the same intent with
`await ctx.operate(WORKSPACE_ID, intent, APPROVAL_OPERATION_ID)` and
`await ctx.recover(WORKSPACE_ID, {operationId: APPROVAL_OPERATION_ID})`.
CLI uses `peerwork operate PROFILE ACTOR SERVICE approval.json`, where the
request names `workspace_id`, `operation_id`, the intent above, and
`expected_fingerprint` retained from `context open`. Recover with
`peerwork context recover PROFILE ACTOR SERVICE recover.json`, naming the same
workspace/fingerprint and `operation_id`. CLI stdout is the outer
`{ok:true,value:…}` envelope; Python and Node return its `value` directly.

See [member entry](agent-entry.md) and the [implementation checkpoint](sdk-agent-runtime-implementation-20261019.md)
for context binding, qualified artifacts and limitations.
