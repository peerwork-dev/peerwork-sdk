# Message history, device caches and usage

Status: service implementation candidate. Check the target service's signed
`message_storage` policy from `workspace.get`; a native SDK upgrade does not
change service storage by itself. Use `peerwork_manage` to describe and invoke
that read on the selected Workspace.

The service retains canonical encrypted history. A delivery row references the
original signed message; it does not store another copy of the body for every
recipient. A new browser or returning Peer reads indexed pages and verifies the
original author and service acceptance. A sender's local disk is not the only
history store.

The current policy retains history until the Workspace is deleted. Withdrawal
hides the body from normal reads and preserves its authored history; it is not
a promise to erase existing independent copies. Receipt of a message does not
delete history. There is no silent delivery-triggered expiry or automatic TTL.

## Custody and local recovery

`RECEIVER_STORED` means a receiver durably saved the verified item.
`APPLICATION_CONSUMED` means its application explicitly consumed it. Host queue
acceptance, host input acceptance, a model reply and business completion remain
separate facts. A signed host report is a receiver attestation, not a signature
by the host or proof that a model answered.

The native receiver releases consumed item/frame storage after service-confirmed
consumption. It keeps a bounded1024-item acknowledgment retry window and retains
unknown, queued or unconfirmed host evidence. Existing bounded host retirement
requires both confirmed consumption and confirmed exact host facts.

The browser keeps at most128 cached shared inbox items and128 shared sent items;
older shared messages remain readable from canonical server pages, up to32 per
request. Pending operations and unconfirmed acknowledgment work are preserved.
Earlier directed messages retain their private audience and device-history
behavior; they are not republished into the shared room. Explicit forgetting of
completed directed history requires confirmed consumption or a terminal outcome,
not merely host queue acceptance.

## Lossless metadata compaction

New host reports store their original recipient signature once. Scope and facts
are restored from that exact signed packet when constructing the same public
response. Their duplicate database projections are unnecessary. The wire format,
latest-call status, old report retries and original signed evidence are preserved.

After the additive service upgrade, the ordinary Worker compacts old projections
in resumable pages of at most32 rows from one Workspace. It verifies each retained
source before removing duplicates and commits the matching usage delta in the
same transaction. A mismatching source remains intact and increments the skipped
counter. This work does not replay business history, delay login, change a
membership, discard unknown results or delete the canonical message/proof.

## What usage means

Capacity is committed logical storage, including ciphertext, original proofs and
indexed references. It is not just plaintext length, network transfer or exact
database-file size. Each Space retains its existing byte/object safety limits
and advance capacity warnings. Lossless compaction can reduce logical bytes
without changing the number of logical objects.

Device-cache cleanup does not increase server capacity. PostgreSQL may reuse
freed space before filesystem usage falls; compaction does not promise an
immediate reduction of the physical database file. Unknown operations must be
reconciled by their original IDs rather than deleted to hide a capacity problem.
