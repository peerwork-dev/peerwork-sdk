# Native release service acceptance

The reusable release builder runs the installed Owner/adopter workflow once per
native target in replica 1. Replica 2 still builds independently for byte
comparison. The gate uses the newly built Python wheel, npm wrapper and native
package, and CLI on the selected target. For musl it runs in the lean installed
consumer container. A tag or publication run cannot assemble a candidate when
any replica-1 target gate fails.

Before dispatching a release, select the current Peerwork service reachable
from all seven hosted runners, including their Linux build containers. The
existing service can be used: the gate creates its own fresh demo identities
and PUBLIC workspaces and does not require a dedicated deployment. Configure
these repository variables:

| Variable | Required value |
| --- | --- |
| `PEERWORK_RELEASE_SERVICE_ORIGIN` | HTTPS service origin with no path, credentials, query or fragment. Loopback HTTP is accepted only when the service is reachable within each target's own runner/container. |
| `PEERWORK_RELEASE_SERVICE_WRITE_SCOPE` | Literal `new-public-workspace`, asserting that the selected service permits creation of fresh PUBLIC demo resources. |
| `PEERWORK_RELEASE_SERVICE_SOURCE_COMMIT` | Optional full 40-character lowercase Git commit for attribution. |

Missing origin or write scope, or malformed configured values, stop replica 1
before its native build. The optional source commit is attribution supplied by
the operator, not an authenticated proof of the remote process; when absent,
service source attribution is unverified. The gate creates fresh local Owner
and recipient identities and a new PUBLIC workspace at the configured origin;
it does not use credentials or an existing workspace. The selected service
must allow enrollment, signed workspace creation, package installation,
admission and actions through the current public HTTP protocol.

The workflow verifies the exact composed proposal/adoption/task package digest,
signed Owner and recipient attribution, candidate/adoption/task effects, exact
candidate references, task relation and head, and same-command CLI retries
after Python and Node actions. The external-service path does not call the
development server's `__test` controls. A local reference-server run remains a
useful affected regression, but does not replace execution on all seven final
native targets against the selected current service.
