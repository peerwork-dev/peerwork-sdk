# Persistent browser access contract

Status: implementation candidate, not a published SDK/service capability yet.
The currently published native SDK0.3.20 does not support this contract. Release
notes must identify the exact qualified service revision and minimum reader SDK
before deployment. See [the browser workflow](backend-structure-browser-candidate.md).

## One authorization, stable device

The existing browser actor signs `peerwork.access-request.v2+jws` with
`v:2`, `kind:BROWSER` and the exact policy:

```json
{"mode":"PERSISTENT","absolute_expires_at":null,"key_binding":"PINNED_UNTIL_AUTHORIZATION_END"}
```

The Owner signs `structure.access.authorize` with `mode:PERSISTENT`,
`authorization_version:2` and the matching `expires_at`. The browser verifies
both signatures. The policy pins those recipient keys until authorization ends;
a bootstrap certificate expiring later does not revoke that explicit permission.
The certificate must still have been valid at the original enrollment.

The candidate advertises `persistent-browser-access-v1` in discovery extensions.
No legacy request is reinterpreted as v2. Finite v1 SESSION and KEYS_ONLY proofs
retain their meanings. Temporary grants and body-key exposure deadlines remain
finite. Persistence grants no extra business responsibility or historical epoch.

Current and retained key deliveries use explicit v2 HPKE domains for these
recipients. Original v1 envelopes and historical signatures remain unchanged.
A temporarily unavailable Owner coordinator leaves current structure available
and reports missing new body keys; it does not fabricate an empty history.

## Upgrade and generation fences

Approving an existing active finite browser uses an exact signed
`upgrade_from:{membership_id,authorization_digest}`. The SDK obtains the current
Owner-only binding through the existing approval query. An exact upgrade retains
that active membership generation and the original finite grant evidence.
Where an old current key has finite exposure, the SDK first resumes one
idempotent key publication; extending permission cannot extend that exposure.

Revoked or expired membership is not silently reactivated. A fresh browser
request and Owner approval create a new generation. New browser writes sign
`expected_membership_id` as part of their immutable business intent. The backend
checks it in the authorization transaction. Fresh persistent generations refuse
unbound mutations. Old packets cannot execute with a newly admitted generation.
A same-generation explicit upgrade may preserve preexisting unbound v1 pending
requests; it never rewrites their IDs or adds a field to an old signed packet.

## End and recovery

End access has a separate saved command and local tombstone. Browser restarts,
other tabs, offline operation and a lost end receipt cannot resume ordinary
access accidentally. Repeated end requests reconcile the same receipt; a device
already revoked may confirm its exact self-end without creating more quota rows.
The end endpoint cannot read data or end somebody else's membership.

Pending business operations remain separate. Verified original commits may be
reconciled after an end. An unsubmitted generation-bound request can be retired
only after a signed absence result and a verified different current generation.
The bounded encrypted local archive keeps the original packet and signed status
query, receipt and result. A network failure or ambiguous legacy generation does
not establish non-application. No recovery creates a substitute identity.

## Cost and migration

Schema21-to22 is additive metadata, with no business-history conversion.
Existing IDs, commands, receipts and accounting stay intact. Current authority
and key eligibility use indexed selected rows. A return visit has no recurring
enrollment transaction, history replay or certificate-renewal service.

The browser uses the existing signed service-time context and short-lived
commands. There is no new bearer token, refresh token or authentication lease.
Possession of the device key and current backend membership remain necessary.
