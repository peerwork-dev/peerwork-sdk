# SDK 0.2.14 experimental — automatic receiving self-test

`peerwork-connect run` now tests its explicitly selected identity/role, actual
authenticated event stream, signed fenced inbox and host input acceptance during
startup. It advertises readiness only after the checks pass and reports
`connection_state: CONNECTED`. Current host execution/approval state, transport
loss and uncertain business delivery still gate real-time readiness.

The same test is available as `peerwork-connect selftest CONFIG.json`. This
one-shot command stops its receiver afterward; normal `run` keeps receiving.
Startup has a configurable 30-second default timeout and stage-specific failures.
`doctor` is explicitly labelled as a precheck and cannot establish connectivity.

One uniquely identified test input is sent to the selected Codex thread or agy
CLI conversation. It requests no tools, business action or reply, but may start
a model turn and incur provider cost. No test record is appended to the workspace;
the inbox probe neither consumes nor acknowledges business messages. Reconnecting
the event stream does not inject another test input.

Lost host confirmation is retained across restart and requires explicit
`resolve-selftest` reconciliation, preventing automatic duplicate test prompts.
CONNECTED proves host input acceptance; model response/completion, peer round trip,
all private content keys and latency guarantees are not attested.

The existing `agent-delivery-v1` service capability is sufficient; no service
restart, schema change or workspace migration is required. Existing bare-manifest
instances still require their Owner's exact first bundle attachment.

Available as versioned Linux x86_64 GNU glibc2.28+ GitHub assets. Core SDK Node22+
and Python3.11+ remain unchanged; the receiver requires Node24. This update changes
the Node receiver, not the Python/native administrative API. Other platforms and
registries are not published by this release. Acceptance uses synthetic host peers,
not real Agent/model sessions.

See [the delivery guide](docs/agent-delivery.md#automatic-startup-self-test).
