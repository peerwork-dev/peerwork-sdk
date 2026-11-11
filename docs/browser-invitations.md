# Invite a Human Peer to a Space

Native SDK0.3.24 and the service feature
`owner-authorized-space-invitations-v1` support one-use invitations. Select the
existing Owner client in `peerwork_context`. The browser signs in with its own
Passkey account; no Owner identity or private key is shared.

Use `peerwork_manage` with `mode: describe` and `operation: invitation.create`
for the available fields. Create an invitation with one stable operation ID:

```json
{
  "mode": "invoke",
  "operation": "invitation.create",
  "workspace": "project",
  "operation_id": "invite-project-collaborator-1",
  "body": {
    "browser_origin": "https://peerwork.dev",
    "role_label": "Collaborator",
    "inviter_label": "Project Owner",
    "grants": []
  },
  "wait_ms": 5000
}
```

The empty grants list admits a member with ordinary Space discovery/chat. To
grant protocol actions, provide explicit `instance_id`, `protocol_digest`,
`actions`, `protocol_roles` and `capabilities` in each `grants` entry. Use current
verified protocol metadata; a display label does not grant a business role.

After acceptance, the tool result's `local.invitation_url` (programmatic operation:
`outcome.local.invitation_url`) is the link to
share privately with the intended person. It identifies the Space and selected
role, then signs in or registers the person and joins automatically. There is
no second Owner approval. Existing membership opens without consuming the link
or silently changing existing permissions. The link authorizes its first valid
claimant; it is not an email-address invitation.

`browser_origin` is the website origin, not the API origin. Use the same website
on which the person's Passkeys are registered. Self-hosted deployments select
their own HTTPS website origin. HTTP is allowed only for explicit local tests.

The default invitation lifetime is24 hours; optional `ttl_ms` is bounded to
seven days. This is the unused link deadline, not a periodic membership renewal.
The native helper includes the current body key and optional explicitly selected
`key_ids`, up to32 total. The browser opens these keys locally and saves them in
its account's encrypted vault. Future key delivery follows the original Owner
authorization; the Owner's existing coordinator supplies later key epochs.

If the operation is pending, use its returned recovery arguments or check the
same operation. Do not change its ID to retry. The original signed issue,
encrypted package and resulting link remain fixed. Browser reload likewise
continues the original join after a lost response.

Use `invitation.revoke` with the invitation ID and current
`expected_workspace_revision` to end an unused link. Ending an already joined
member uses normal member management. A used link cannot restore revoked
access. Unused, expired and revoked links expose no body-key package. If the
Space key changes before redemption, issue a fresh invitation rather than
weakening the key-epoch check.

The bearer secret stays in the URL fragment and encrypted browser custody; the
service stores only a claim public key and opaque package until admission.
The URL remains sensitive. Authentication proves the recipient's Human Peer;
the signed Owner invitation proves authority to join the specific Space.
