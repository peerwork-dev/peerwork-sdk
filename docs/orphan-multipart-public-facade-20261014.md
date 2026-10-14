# Multipart orphan Owner facade candidate

This source-only facade is based on frozen runtime `b1a3b207464e80251298d377350a347d3fd0fe55`.
The runtime's service acceptance is separate and pending. The changes are limited
to the Python, Node, and CLI public routes and their native dispatchers; they
do not alter attachment proofs, packets, or protected storage.

For a stopped old Owner with a packetless stage marker at index greater than
zero, callers provide complete material, protected source paths, workspace ID,
and expected Owner actor/key pins to `inspect_multipart_orphan_package_stage` (Python),
`inspectMultipartOrphanPackageStage` (Node), or
`owner-stage-multipart-orphan-inspect` (CLI). The result exposes command/source
IDs and hashes, source sequence, part index/count, the whole TS-state digest,
and local status. `ORPHAN_NO_PACKET` describes an absent original packet at
the observed signed head; `APPLIED_IN_SIGNED_REPLAY` describes an exact marker
seen in replay. Neither status by itself authorizes attachment or replan.

Attach requires the explicit inspected orphan command ID, the exact whole
TS-state digest, and the same full material. Python and Node have a distinct
multipart-orphan attach method; the CLI uses
`owner-stage-multipart-orphan-attach`. The native entrypoint refuses pending
stage selection or a missing orphan selection/digest before calling the
runtime. The runtime verifies the source and saves a restricted attachment
without submitting the original packet. Existing one-part orphan, saved
pending-packet, and kernel-command interfaces are unchanged.

Replan stays a separate call using the attachment ID and original command ID.
Its optional material is for exact saved-plan continuation. The returned
`orphan_replan_stage_id` is the new stage ID to pass to the private installer
only after signed completion and ordinary `ATTACHED` status; a merely saved
replan remains restricted. Material is accepted as JSON text (CLI: material
file) and is absent from inventory, attachment results, and error messages.
Python async routes use the existing cancellation helper, Node forwards
`AbortSignal`, and CLI uses its existing interrupt monitor.

Focused source-boundary tests exercise sync/async Python routing, Node
selection/unknown-key rejection and AbortSignal forwarding, strict TypeScript
method and result typing, and CLI exact typed preflight before any state or
network access. They do not establish installed package or service behavior,
native macOS/Windows behavior, or natural Agent workflow compliance.

The Rust 1.89 offline locked four-crate check passed in session `41801`
against `b1a3b207` plus these six facade files. Python and Node wrapper
source tests passed, as did a strict TypeScript 7 declaration consumer with
`--ignoreConfig`, bundler resolution, and the pinned Node type roots. A
task-local debug CLI build passed in session `15355`; the CLI test verified
exact `INPUT_INVALID` for conflicting or missing selection before state
creation, and confirmed both verbs in machine-readable help. No service was
started by these tests.

Setup/test-harness deviations are preserved separately: bare `node` was not
on the host PATH, so the accepted bundled Node 24 binary ran the test; the
first TypeScript invocations lacked TS 7's `--ignoreConfig`, compatible
module resolution, and Node type roots; the first Python mock async test
entered this environment's `asyncio.to_thread` shutdown wait, so the final
source-boundary test substitutes a direct async invoker and verifies routing
only. These failures do not establish a product or runtime result.
