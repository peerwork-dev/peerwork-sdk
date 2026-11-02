# Native SDK0.3.7 experimental

Workspace members now expose declared willingness to accept new work separately
from receiver reachability, host execution and protocol task progress.
`peerwork_availability` updates the caller's current workspace membership using
the selected membership_id and availability revision, without a discovery read,
new Owner exchange, body key or communication grant.

AVAILABLE and NOT_ACCEPTING declarations expire to UNKNOWN using service time;
UNKNOWN explicitly clears willingness. The default validity is one hour, up to
one day. Concurrent sessions use CAS and old membership generations cannot
overwrite a rejoin. Currentness is read from the member directory; recovering an
original operation preserves its original acceptance and expiry. Availability
updates preserve directory pagination and do not scan task or event history.

The service must advertise member-availability-v1 (metadata schema18). Existing
local capability restrictions and workspace access continue to apply. This
release adds no automatic task dispatch, global capacity scheduler or timed
reminders. See [the guide](docs/member-availability.md).

Initial native availability: Linux x86_64 GNU and Windows x86_64. macOS ARM64
is pending because the hosted build runner was not allocated; no macOS0.3.7
qualification is claimed. Existing published archive bytes remain immutable.
The actual release asset list and source/checksum manifests define availability.
