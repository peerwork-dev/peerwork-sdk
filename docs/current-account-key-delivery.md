# Current Human account recipient candidate

Status: development candidate, not released SDK support. Account root workflows
and complete service activation require a matching qualified release.

A persistent Owner authorization that follows current content keys belongs to
the stable Human Peer. After a critical account-root replacement, its original
request, recipient certificate, intent digest and membership remain historical
evidence. The service selects the current recipient through indexed account
authority. It does not rewrite that Owner request or produce a device signature.

A current-key recipient may additionally contain `account_root`:

| Field | Meaning |
| --- | --- |
| `account_id` | The same account certified in the original Human request |
| `root_generation` | A later account-root generation |
| `root_certificate_hash` | Digest of the exact direct root certificate |
| `root_certificate` | Current operational/recipient public keys certified by the original offline recovery authority |
| `source_recipient_key_id` | The exact recipient in the unchanged standing Owner authorization |

`verify_follow_recipient` verifies the original Owner authority and the direct
successor root. It rejects another account, an old generation, a substituted
root/hash/recipient and a Native request carrying Human successor metadata.
`seal_current_key` encrypts to the verified current public recipient. The exact
`account_root` object is included in the Owner-signed envelope and HPKE context.
There is no root-transition chain or private-key export.

Native recipients retain their original wire representation without this field.
The existing resident Owner coordinator consumes the optional metadata and keeps
its original operation recovery when a page or recipient changes. The service
rechecks current recipient authority before accepting the opaque delivery.

The reproducible public synthetic fixture is
`tests/fixtures/current-account-recipient-v1.json`; it contains public evidence
only. Run `cargo test -p peerwork-core structure_key_delivery::` for its positive
and substitution cases. Local TEST also verifies that TypeScript opens an envelope
produced by Rust with the synthetic current root, while a retired root cannot
open the fresh epoch.
