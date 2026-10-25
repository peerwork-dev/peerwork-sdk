# Original document time — source candidate

This implemented capability has passed local acceptance. It is not yet a
production availability statement or a released SDK version. Require
`signed-document-time-v1` in discovery with `backend-structure-v1`.

## Import through an ordinary protocol action

```js
const outcome = await kernel.executeStructureIntent({
  action: 'structure.action',
  workspace_id: workspaceId, instance_id: instanceId,
  protocol_digest: protocolDigest,
  expected_instance_revision: instanceRevision,
  idempotency_key: 'import-source-document-42',
  body: {
    action_id: 'document.import', // an action defined by your protocol
    structure: {title: 'Original document'},
    document_times: [{
      record_index: 0,
      created_at: '1998-12-31T16:59:59.123456789-07:00',
      updated_at: '2001-02-03T04:05:06.789Z'
    }]
  },
  plaintext_contents: [{record_index: 0, text: originalText}]
});
```

Python `execute_structure_intent`, CLI `kernel intent`, and selected Context
`protocol.action` use the same native implementation. No special import grant
or protocol name is built in: the protocol must define the selected action,
its schema and output, and the signer must hold its ordinary write grant.
The optional body is encrypted by the client using the existing PRIVATE path.
Business rules cannot read the encrypted body or this provenance metadata.

Each selection addresses one produced record by zero-based output index. Supply
one to eight unique selections, with `created_at`, `updated_at`, or both. Dates
must be valid RFC3339 strings; original offsets and up to nine fractional digits
are preserved exactly. Missing fields become null in verified output. Invalid
calendars, unknown fields, duplicate indices and selections without a produced
record are rejected. Native validation and capability checks run before crypto
preparation or mutation allocation. `DOCUMENT_TIME_INVALID` is non-retryable,
with `NOT_SUBMITTED` and `CORRECT_DOCUMENT_TIMES` recovery.

## Verification and time semantics

Selected record reads and pages expose `source.document_time`. It is bound to
the original author's signed action, not merely the service response. The SDK
and browser reject substituted dates even if the enclosing service receipt is
valid. Records without imported dates retain their existing source format.

Original dates are author claims, not proof that Peerwork observed the document
at that historical time. Service `created_at` remains the actual admission time.
Guard time, leases, authorization expiry and ordering never use imported dates.
The UI separates original source time from submission time and identifies the
importing signer without claiming that signer was the historical author.

For PUBLIC member outputs, only the selected output's own dates enter its
independently disclosable author signature. Another output's private dates or
business arguments are not disclosed. An Owner-curated snapshot automatically
copies verified source dates and binds them to the Owner's publication signature;
its public historical-time assurance is a publisher attestation. It does not
expose the complete PRIVATE source command to claim public author verification.
Native Changelog entries expose `document_time`, `document_time_assurance`
(`AUTHOR_SIGNATURE` or `PUBLISHER_ATTESTATION`) and separate `submitted_at`.

Withdrawing a record removes its online PUBLIC entry and preserves the normal
audit semantics. Whole-workspace deletion removes date metadata with existing
record/command/publication rows. No new tables or identity migration are needed;
PostgreSQL schema remains11. Existing records are not silently backdated.

## Availability

Local acceptance covers installed Node/Python/CLI/Context, PostgreSQL actions,
PRIVATE bodies, PUBLIC author outputs and Owner snapshots, mobile/no-JS HTML,
reloaded PRIVATE browser reads and valid-receipt tamper refusal. Exact production
service and SDK versions will be announced with the release. Development0.1.11
artifacts must not replace published0.1.11.
