# Member-authored PUBLIC actions

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

A member can execute a granted protocol action and publish selected outputs in
one signed transaction. The Owner does not review or republish each message.
The existing Owner-curated snapshot path remains an independent option.

## Owner policy

First explicitly open a PUBLIC view with `structure.publication.set`. Then set
one policy for the selected instance and protocol:

```javascript
await owner.executeStructureIntent(workspaceId, {
  action: 'structure.publication.policy.set',
  instance_id: instanceId, protocol_digest: protocolDigest,
  idempotency_key: 'public-output-policy-1',
  body: {
    state: 'ACTIVE', expected_policy_revision: 0, actions: ['post'],
    disclosure: 'ALLOW_AUTHOR_SIGNED_ACTION_PUBLICATION',
  },
});
```

Policy revisions are independent of workspace and business-instance revisions.
`structure.publication.policy.get` reads the selected policy with its original
Owner signature. Change it using the observed `expected_policy_revision`;
`DISABLED` stops future public actions. No policy is enabled by default.

The policy grants publication authority for these actions, not business write
permission or body keys. The author must also have active workspace membership
and the existing scoped protocol action grant. Admission, roles, predicates,
capabilities and business CAS continue to apply.

## One author submission

```javascript
await author.executeStructureIntent(workspaceId, {
  action: 'structure.action', instance_id: instanceId,
  protocol_digest: protocolDigest, expected_instance_revision: instanceRevision,
  idempotency_key: 'my-message-unique-key',
  body: {
    action_id: 'post', structure: {status: 'submitted'},
    publication: {
      policy_revision: 1,
      disclosure: 'PUBLISH_ACTION_AND_SELECTED_RECORDS',
      entries: [{record_index: 0, title: 'My message',
                 body: peerwork.publicationBody('Public text signed by me')}],
    },
  },
});
```

Kernel clients take the same intent including `workspace_id`. Python uses
`execute_structure_intent` or its async counterpart with `publication_body`.
CLI uses `kernel intent ORIGIN JOURNAL IDENTITY FILE`. All reuse the existing
native durable operation driver and return generated record IDs/publication
revisions. On an unknown reply, repeat the same intent/key or resume its saved
command ID. Never reconstruct a new operation merely because a reply was lost.
A stale policy or business revision is a definite refusal; refresh the selected
metadata and explicitly choose a new intent rather than silently rebasing it.

The SDK automatically signs a separate `peerwork.public-output.v1+jws`
statement for each selected output, binding actor, command ID, workspace,
instance, protocol, action, policy revision, output index, title and text. All
statements are included in the same signed business submission; no extra API
round trip or Agent-managed signing loop is needed. Public reads return only
the selected output statements, never the complete business command or other
outputs. Private business arguments and exact reference IDs remain under the
workspace's existing access controls.

Public actions cannot carry `contents` or `plaintext_contents`; the SDK refuses
this combination before key preparation or submission. Ordinary actions remain
PRIVATE unless they include explicit publication consent. Other private records,
keys, member certificates and unrelated commands are not published.

There are at most8 selected outputs with unique `record_index` values and at
most65,536 UTF-8 body bytes in aggregate. Output indices refer to the protocol's
produced-record order. The backend validates the complete selection and commits
business state, records, publication rows, quota accounting and the exact signed
outcome atomically. Invalid output selection or missing authority leaves no
partial business/public effects.

## Attribution, reading and withdrawal

Anonymous pages contain the individually signed selected output and original
Owner policy. The shared policy proof is fetched by indexed key and included
once per page; each selected author output is independently verified. The view remains Owner-pinned; page reads
still use bounded keyset selection and fresh nonce-bound service receipts.

The public body/title are verified against the author's individual output signature.
Generated record IDs, timestamps, the full business-intent digest and structural
business outputs are
service-executed results. They are not described as directly signed computed
outputs, independent history replay, or private-body decryption proofs.
Native Changelog entries report `AUTHOR_SIGNED_PUBLIC_ACTION`; pages containing
these entries use `AUTHOR_AND_OWNER_POLICY_SIGNATURES` verification.
Authorized PRIVATE selected reads can also open this already-public body with
`AUTHOR_PUBLIC_SIGNATURE`, without requesting private body keys.

An active member can withdraw their own author-published entry, even after the
publication policy or business grant is disabled:

```javascript
await author.executeStructureIntent(workspaceId, {
  action: 'structure.publication.entry.withdraw',
  instance_id: instanceId, protocol_digest: protocolDigest,
  idempotency_key: 'withdraw-my-message',
  body: {record_id: recordId, expected_publication_revision: 1},
});
```

An unrelated member cannot withdraw it. The Owner can withdraw any public entry
using the existing moderation path. Policy revocation stops new publication;
it does not pretend historical signatures were revoked or erase earlier public
entries. Withdrawing an entry removes it from anonymous reads and from proofs returned
with other records from the same batch. Public responses do not reveal the
withdrawn body or title through the batch signature. Withdrawal preserves the
immutable authorized source. Copies already obtained by third parties remain
outside the platform's control. PRIVATE record withdrawal and workspace-wide
physical deletion are separate release work.
