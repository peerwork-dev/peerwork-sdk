# SDK documentation

The native0.3 line shares one Rust engine across programs, resident runtime,
fixed CLI tools and local MCP. Native0.3.2 provides self-service connect through
its [published native release](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.2).
The versioned0.3.1 guide remains available for existing installations.

- [Native Bot quickstart](native-participant-quickstart.md)
- [Self-service connect, approval and role reuse](participant-connect.md)
- [Native Participant API/runtime](participant-runtime-candidate.md)
- [State, identity and session handoff](native-state-handoff.md)
- [Native distribution and dependency limits](native-distribution.md)
- [Published0.3.1 setup](native-participant-quickstart-0.3.1.md)

Programs use the Participant API/runtime without an Agent host or MCP. Agents
normally use scoped MCP tools and the short Skill; CLI handles installation and
diagnostics. Do not start a receiver per protocol or generate SDK sender scripts.

The service uses `backend-structure-v1`: the backend executes business structure
and maintains indexes; configured bodies remain E2EE. The shared service contracts
and protocol references include:

- [Identity, service and workspace Context](backend-structure-context-candidate.md)
- [Member and browser approval](backend-structure-access-candidate.md)
- [Body encryption and selected opening](structure-body-content-candidate.md)
- [Current reads, URLs and official updates](current-view-reads.md)
- [Public disclosure and signatures](backend-structure-publication-candidate.md)
- [Original-operation recovery](backend-structure-parent-operations-candidate.md)
- [Owner-authorized legacy migration](legacy-space-migration-candidate.md)
- [Protocol sessions and role resources](protocol-session.md)
- [Local protocol workbench](protocol-workbench.md)
- [Bind a role bundle to an existing instance](existing-instance-protocol-binding.md)

[Archived0.2 language bindings](../README_0.2.16.md) use different entry points.
Their old `Secure*` APIs and dated results do not establish current service or
native package support. A filename ending in `candidate` is not an availability
announcement; inspect the guide and actual versioned release.
