# Receiving recovery and diagnosis

The receiver distinguishes recoverable resource pressure from invalid evidence
and changes to receiver authority. A ready host does not prove that receiving is
working. Check each observation independently before reporting the participant
as reachable.

When upgrading a receiving installation, follow the
[original-stack guide](host-bridge-recovery.md#upgrade-the-original-receiving-stack).
Frontend and runtime versions do not inventory an independently running bridge.
Check the actual components and required capabilities, retaining their original
state and destination; a newly installed binary alone does not establish that
the live stack was upgraded.

## Resource pressure

The receiver retries `RESOURCE_EXHAUSTED` and
`CAPACITY_RESERVATION_EXHAUSTED` HTTP diagnostics with bounded backoff. It stays
in `RECONNECTING` with the original error code rather than latching `BLOCKED`.
Capacity retries start at two seconds and grow to at most thirty seconds.
No runtime restart, new identity, replacement mailbox or checkpoint reset is
needed after capacity returns.

A temporary acknowledgment upload failure instead retains an already verified
receiving link and appears in the independent `acknowledgment_code` field. This
field clears only after an acknowledgment succeeds; it does not attest model
processing. Lease, authority and verification failures still invalidate the
appropriate receiving path.

This policy applies to receiving maintenance: mailbox inspection, the original
claim, lease renewal, acknowledgments and stream grants. An uncertain claim
retains its frozen command ID, receiver ID and receiver fence. Acknowledgments
are retried from durable local facts. A fresh maintenance observation does not
resubmit an unrelated business operation.

General operation recovery remains unchanged. An unverified HTTP resource error
does not prove that a mutation had no effect. Preserve the original operation
and reconcile it. A signed terminal refusal is not converted into a transient
result. Invalid signatures, changed receiver generations and authority failures
retain their existing isolation requirements.

## Local notification storage

Native 0.3.30 repairs accumulating Runtime/bridge call evidence. This is separate
from the service resource retry policy above. Follow the
[notification retention guide](notification-state-retention.md), upgrade both
original resident components and keep their state. Completed notifications can
be reclaimed across old sequence holes; a pending application item does not pin
every later completed frame. Do not delete messages or clear unknown operations
to force free space. Actual outstanding work still applies backpressure.

## Read observations separately

| Observation | Meaning | What it does not prove |
| --- | --- | --- |
| Host `LIVE`, `ready=true` | The selected host recently responded | The mailbox stream is verified or renewed |
| `receiver_link_verified=true` | The selected receiver verified its receiving link | A model read or answered a message |
| `checkpoint` | Last durably accepted receiver item | The current server frontier or application completion |
| `key_current=false` | No sufficiently recent key-state observation | Keys were deleted or the identity must be replaced |
| `reporting_code` | Uploading host-call facts encountered a problem | The original host input should be injected again |
| `acknowledgment_code` | Uploading durable receiver/application acknowledgment facts is delayed | The receiving stream failed or the message was not saved locally |
| `verification_failure` | Evidence verification has been isolated | Resource pressure can safely clear that isolation |
| `LOCAL_SCOPE_DENIED` | The selected local client rejected an operation before HTTP | The service rejected it, storage is full or a member is offline |

An idle mailbox need not advance its checkpoint. Compare it with a fresh server
frontier or a known message before diagnosing a stalled stream. Inspect the
mailbox lease against server time; a stored `ready=true` with an expired lease
is not current reachability.

## Investigate a stalled receiver

1. Capture a fresh receiver snapshot and its SDK/runtime version. Retain the
   original error code, checkpoint, key-state code and verification diagnostic;
   do not replace them with a single online/offline flag.
2. Check the signed Workspace capacity response. Inspect both the byte and
   object dimensions while the service enforces them. Also distinguish mailbox
   backlog exhaustion and global capacity reservation from Workspace storage.
   A generic resource code alone does not identify the exhausted resource.
3. Correlate the action, command ID and failure time with service telemetry.
   A successful read now does not explain an earlier rejected write; an old
   local blocker is not evidence of a new service rejection.
4. After removing the limiting condition, verify lease renewal, link
   verification, fresh key state and receipt of a known pending message. Preserve
   the original mailbox, generation and checkpoint throughout recovery.
5. For an older runtime that remains latched after capacity has returned,
   restart that same native runtime using its existing protected state. Merely
   reading status or attaching another listener does not reset its in-memory
   blocker. Never delete its journal, keys or pending operations to make the
   status appear healthy.

Automatic recovery must not acknowledge an unverified message, advance a cursor
past unaccepted data, clear a signature quarantine, or replace unknown business operations. Controlled notification redelivery uses
the same frozen message/destination with durable attempt IDs; original unknown
host facts remain. Host receipt and model completion remain separate.

## Local capability denials

Inspect `error.details.action`, `scope` and `restricted_by` before changing
configuration. A denial of `structure.members.read` can mean a missing operation,
an instance/protocol-only endpoint, a Workspace mismatch, or a mailbox-only
delegation that cannot read the collaboration directory. Merely adding that
operation to an allowlist does not correct the other dimensions.
Upgrading or restarting a binary does not enlarge an already issued immutable
client capability.

The normal Workspace participant reuses its existing client through the shared
lifecycle, including older profile launches. A known generated projection is
normalized only through its authenticated original issuer after a safe
unsubmitted denial; the failed request is retried once and old clients remain
available for original-operation recovery. No Workspace permission request or
identity migration is part of this repair.

A profile cannot grant itself a broader parent. Missing issuer/policy evidence
returns `ORIGINAL_ISSUER_SELECTION_REQUIRED` with one explicit local-source
continuation. Deliberate delegations remain unchanged. See
[existing-client recovery](existing-client-tools.md); do not manually edit action
lists or create another MCP/receiver to bypass the failure.
