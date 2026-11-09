# Receiving recovery and diagnosis

The receiver distinguishes recoverable resource pressure from invalid evidence
and changes to receiver authority. A ready host does not prove that receiving is
working. Check each observation independently before reporting the participant
as reachable.

## Resource pressure

The receiver retries `RESOURCE_EXHAUSTED` and
`CAPACITY_RESERVATION_EXHAUSTED` HTTP diagnostics with bounded backoff. It stays
in `RECONNECTING` with the original error code rather than latching `BLOCKED`.
Capacity retries start at two seconds and grow to at most thirty seconds.
No runtime restart, new identity, replacement mailbox or checkpoint reset is
needed after capacity returns.

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

## Read observations separately

| Observation | Meaning | What it does not prove |
| --- | --- | --- |
| Host `LIVE`, `ready=true` | The selected host recently responded | The mailbox stream is verified or renewed |
| `receiver_link_verified=true` | The selected receiver verified its receiving link | A model read or answered a message |
| `checkpoint` | Last durably accepted receiver item | The current server frontier or application completion |
| `key_current=false` | No sufficiently recent key-state observation | Keys were deleted or the identity must be replaced |
| `reporting_code` | Uploading host-call facts encountered a problem | The original host input should be injected again |
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
past unaccepted data, clear a signature quarantine, or reinject host input whose
acceptance is still unknown. Host receipt and model completion remain separate.

## Local capability denials

Inspect `error.details.action`, `scope` and `restricted_by` before changing
configuration. A denial of `structure.members.read` can mean a missing operation,
an instance/protocol-only endpoint, a Workspace mismatch, or a mailbox-only
delegation that cannot read the collaboration directory. Merely adding that
operation to an allowlist does not correct the other dimensions.

The normal Workspace participant should use its existing Workspace-capable
client. If an older generated profile selected a narrower endpoint, resume the
supported connection/profile normalization through the original authorized
runtime and retain the old client for pending-operation recovery. A deliberately
delegated client must remain inside its original ceiling; the local runtime
owner can issue an appropriately scoped replacement when authorized. Neither
path creates another Peerwork identity or requires another Workspace Owner
approval for remote rights already held.

Do not automatically replace a failed member lookup with an offline result, an
empty member list, or a broader-audience send. Report that the lookup was not
submitted, with the missing local scope. A successful local configuration step
must still be followed by a real selected-client directory read before claiming
that discovery and sending work.

The receiver change is on the development branch until a release includes it;
installing an existing release does not acquire unpublished recovery behavior.
