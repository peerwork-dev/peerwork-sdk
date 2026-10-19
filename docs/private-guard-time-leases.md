# PRIVATE trusted time and lease support

The platform integration guide is [PRIVATE trusted time and lease support](https://peerwork.dev/docs/private-guard-time).
It documents the Owner activation step, the supported preflight example, and the
acceptance required before bounded-duration leases can be claimed. The example
runs in the product TypeScript repository; this native SDK repository does not
ship that product runtime or a standalone equivalent script.

| Interface | Version and availability | Scope |
| --- | --- | --- |
| Service guard time | `signed-private-guard-time-v1` | Opt-in PRIVATE v3 service admission attestations. Presence in authenticated discovery does not enable a workspace. |
| Published native SDK | [0.1.2 experimental.39199024029](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.1.2-experimental.39199024029), source `1ee448b56feeac40b3ac385c79ab4942d033d7d8` | Guarded PRIVATE action submission with a stable operation ID; public Owner policy enablement facade absent. |
| This source candidate | 0.1.3, publication pending | Adds current-page reads and original guard-time evidence verification. It does not add bounded-lease operators or Owner guard-time enablement. |
| Product TypeScript API | `SecureAgentClient.enableGuardTime` | Owner policy activation; no unified published native SDK minimum version is asserted. |
| Bounded-duration lease extension | Not implemented/released | No SDK version or automatic service-signing-key rotation is promised. |

In Python, existing guarded submissions use
`SecurePrivateActionClient.submit(..., operation_id=...)`; in Node they use
`openSecurePrivateActions(...).submit(..., {operationId: ...})`. Use the existing
protected identity/profile and exact-operation recovery. These calls do not
activate a workspace's guard-time policy.

Owner activation uses the product TS API with the current policy's
`expectedPolicyHash`, trusted discovery `audience` and `receipt_public_key`, and
`disclosure: 'GUARD_WINDOW'`. It signs a policy update and
`secure.guard-time.enable` commit. Activation requires PRIVATE policy v3 and
Owner authority; `ALL_COMMITS` also covers administration and time-free actions.
Historical untimed commits keep their original verification rules. Unsupported
peers must reject new timed policies. The current API does not permit changing
an activated guard-time policy's service pins in place.

Supported guard-time v1 predicates are conjunctions of direct `lt`, `lte`, `gt`
or `gte` comparisons between service time and time-free safe integers, in a
single-variant timed action. PRIVATE preflight rejects `time_add`, timed
OR/NOT/equality, time-dependent effects and multiple variants in a timed action.
A local `issued_at` value or client clock does not establish service admission.

The desired lease requirements remain future work: acquire must enforce
`MIN <= expires_at - T <= MAX`; renew must enforce `T < old_expires_at`,
`new_expires_at > old_expires_at` and the same duration bounds; reclaim requires
`T >= old_expires_at` and a fresh generation. Direct deadline comparisons alone
do not implement these complete rules. Old-generation work must be fenced by
the user's business protocol or downstream consumer. The platform must first
supply an executable supported example and exact service/SDK versions; the user
then owns the business protocol, narrow permissions and integration acceptance.
