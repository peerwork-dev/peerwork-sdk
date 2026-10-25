# Body-only SDK content

Service support: production `backend-structure-v1`, deployed 2026-10-25.
SDK/CLI support: [0.2.1 release assets](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.2.1) for Linux x86_64
GNU (glibc 2.28+), Node 22+ and Python 3.11+. Require the named capability in
service discovery. Other binary platforms are not part of this release.
The historical `-candidate` filename is retained to preserve documentation links.

## One producer call

The candidate Kernel `executeStructureIntent` request accepts an optional
`plaintext_contents` array outside its service-readable `body`. Context v2
`protocol.action` accepts the same field:

```javascript
await context.operate(workspaceId, {
  kind: 'protocol.action',
  instance_id: instanceId,
  protocol_digest: protocolDigest,
  expected_instance_revision: revision,
  action_id: 'post',
  values: {topic: 'release'},
  plaintext_contents: [{record_index: 0, text: 'Private document body'}],
}, 'post-release-42');
```

The native SDK selects the existing protected local key, encrypts before
submission, signs the command, drives submission and verifies its result. Only
structure and authenticated ciphertext enter the signed request. The service
cannot use plaintext in predicates or effects. A missing key is reported as
`CONTENT_KEY_MISSING`; the SDK does not silently mint a replacement.

There are at most eight attachments. Each UTF-8 text body is limited to
65,536 bytes; the combined plaintext size of all attachments in one action is
also limited to 65,536 bytes. The native SDK automatically serializes ciphertext
larger than 8,192 base64url characters as canonical `ciphertext_chunks`. This is
one AES-GCM envelope, one signed action and one business record per output;
chunks are not separate business records or Agent-managed upload transactions.
There are at most eleven segments, each at most 8,192 characters. Structural
fields retain their existing 8,192-byte scalar budget and 16-KiB input budget.
The ordinary signed-packet and selected-response budgets are unchanged.

The service advertises `chunked-content-bodies-v1` and the exact limits
`contentBodyBytes`, `contentBatchBytes` and `contentCiphertextChunkBytes` in
discovery. The SDK rejects unsupported larger bodies and aggregate overflow
before key initialization, submission or durable outbox creation. Small inline
envelopes preserve their existing signed format. Bodies or file attachments
larger than 64 KiB require a separate future transport; do not fragment business
records to bypass the declared limit. `contents` (already sealed) and
`plaintext_contents` are mutually exclusive on one request.

## Stable retries

Before any submission or authorization-time network await, the SDK saves one
exact ciphertext under the original command ID. Concurrent producers elect the
first saved packet. A repeat with plaintext authenticates and decrypts that
packet locally, compares the requested bytes, and reuses its ciphertext. Other
business fields are still compared under the existing immutable-intent rules.
Different text or business fields return a conflict; the SDK never rebases them.

The provisional saved authorization is renewed from signed service time before
submission when necessary. Authorization renewal preserves the ciphertext and
logical operation. After transient mutation reply loss, the SDK also attempts
one indexed observation of that exact saved operation within the same call,
without replaying history or inventing a new command. If no signed outcome can
be established, the operation remains pending; a missing observation does not
prove non-commit. `resumeStructureIntent` / `recover` uses the saved packet and
does not require the original plaintext or local body key. An active-key change
does not change an already prepared request's key, nonce or ciphertext.

Plaintext is not persisted in the operation journal or copied into error
continuations. Caller-owned text remains in the caller's memory. Selected
decrypted native buffers and key material use zeroizing storage.

## Protected indexed keys

The language/Context body key cache is separate from the transport journal,
beside the selected identity with extension
`<SHA256-of-normalized-origin>.content-keys.sqlite`. It requires the same protected directory,
file and supported-platform checks. Its immutable origin binding and
`(local_key_id, workspace_id, key_id)` primary key isolate service, identity and
workspace selections. A separate current-key register uses point lookups.
Historical keys remain available for selected old-body decryption. Opening the
cache does not load all keys or audit the complete history.
Changing Context or transport-journal paths with the same identity and service
reuses this key cache. It does not trigger identity or historical-key migration.

Node `kernel.ensureLocalContentKey(workspaceId)`, Python
`kernel.ensure_local_content_key(workspace_id)` (and async variant) and CLI
`kernel local-content-key ORIGIN JOURNAL IDENTITY WORKSPACE_ID` explicitly
initialize or reopen one local key. They return public key identifiers only,
do not rotate an existing key, grant membership, deliver to another actor, or
assert that another reader possesses it. These are local producer/fixture
building blocks; the source candidate now connects Owner-authorized Agent
delivery and selected automatic key retrieval through Contexts.

The Rust runtime can import a separately protected raw key file with an expected
key commitment and current-selection check. Import does not establish remote
authority or provenance. It never rewrites the source or discards old keys.

## Authentication and current-state assurance

AES-256-GCM binds the execution profile, workspace, instance, protocol digest,
original author, command ID, action ID and record index. The key identifier is a
domain-separated commitment to a uniformly random 256-bit key. Envelope format,
AAD digest, nonce size and ciphertext budget are checked before decryption.

Core `authored_structure_content` derives the context and ciphertext from a
verified original-author signature. Runtime `open_authored_body` selects the
corresponding local key directly. Selected service receipt verification binds
the returned record to that author and index separately. Body authentication
does not turn service-selected structural state into independently replayed
history, grant membership or prove business correctness from content.

Selected record reads and pages retain the verified service ciphertext and add
`opened_contents` separately. Entries have `OPENED` (with text and
`AUTHOR_SIGNATURE_AND_AEAD`), `NO_CONTENT`, `KEY_UNAVAILABLE`,
`AUTHENTICATION_FAILED`, `BODY_INVALID`, `KEY_STATE_INVALID` or
`UNSUPPORTED_ENCODING` state. Missing or damaged keys do not discard readable
structure or trigger a legacy history replay. Plaintext is not inserted into the
signed service result or persisted in the transport journal. Context v2 returns
the same separate local opening results. Selected Owner key delivery is connected in the source candidate. Canonical
current-key policy, revocation/rotation and automatic distribution now have
installed-package qualification. Browser UI and final release work remain.
