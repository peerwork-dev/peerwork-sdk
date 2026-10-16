# Native release service acceptance

The reusable release builder runs the installed Owner/adopter workflow once per
native target in replica 1. Replica 2 still builds independently for byte
comparison. The gate uses the newly built Python wheel, npm wrapper and native
package, and CLI on the selected target. For musl it runs in the lean installed
consumer container. A tag or publication run cannot assemble a candidate when
any replica-1 target gate fails.

Before dispatching a release, provision an isolated instance of the current
Peerwork service reachable from all seven hosted runners, including their Linux
build containers. Configure these repository variables:

| Variable | Required value |
| --- | --- |
| `PEERWORK_RELEASE_SERVICE_ORIGIN` | HTTPS service origin with no path, credentials, query or fragment. Loopback HTTP is accepted only when the service is reachable within each target's own runner/container. |
| `PEERWORK_RELEASE_SERVICE_SOURCE_COMMIT` | Full 40-character lowercase Git commit of the provisioned service source. |
| `PEERWORK_RELEASE_SERVICE_WRITE_SCOPE` | Literal `ephemeral-isolated`, asserting that this endpoint is reserved for disposable acceptance writes. |

Missing or malformed variables stop replica 1 before its native build. The
source commit variable is an operator assertion: the SDK cannot determine the
remote process's source commit from its HTTP protocol. The service deployment
record must independently bind the configured endpoint to that source. The gate
creates fresh local Owner and recipient identities and a new PUBLIC workspace
at the configured origin; it does not use credentials or an existing workspace.
The isolated service must allow enrollment, signed workspace creation, package
installation, admission and actions through the current public HTTP protocol.

The workflow verifies the exact composed proposal/adoption/task package digest,
signed Owner and recipient attribution, candidate/adoption/task effects, exact
candidate references, task relation and head, and same-command CLI retries
after Python and Node actions. The external-service path does not call the
development server's `__test` controls. A local reference-server run remains a
useful affected regression, but does not replace execution on all seven final
native targets against the provisioned current service.
