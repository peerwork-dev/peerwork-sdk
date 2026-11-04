# SDK documentation

The native0.3 line shares one Rust engine across programs, resident runtime,
fixed CLI tools and local MCP. Native0.3.9 adds portable permission requests, combined admission/rights approval
and explicit inbox consumption alongside existing member tools in its
[exact public release](https://github.com/peerwork-dev/peerwork-sdk/releases/tag/v0.3.9).
The versioned0.3.2 guide remains available for that older installation.

- [Native Bot quickstart](native-participant-quickstart.md)
- [Self-service connect, approval and role reuse](participant-connect.md)
- [First-use discovery and exact host support](participant-discovery-candidate.md)
- [Published0.3.2 setup](native-participant-quickstart-0.3.2.md)
- [Attach tools to an existing client without migration](existing-client-tools.md)
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
- [Native tool capabilities and management](agent-tools.md)
- [Native protocol participation and role resources](protocol-session.md)
- [Local protocol workbench](protocol-workbench.md)
- [Bind a role bundle to an existing instance](existing-instance-protocol-binding.md)
- [In-place protocol upgrades](in-place-protocol-upgrades.md): unpublished service
  and native SDK candidate; keep old work pinned while changing the instance default.

[Archived0.2 language bindings](../README_0.2.16.md) use different entry points.
Their old `Secure*` APIs and dated results do not establish current service or
native package support. A filename ending in `candidate` is not an availability
announcement; inspect the guide and actual versioned release.

## Shared-project onboarding follow-up

Native0.3.4 is published with exact native assets/checksums independently verified.
See [shared projects and private state](participant-connect.md#shared-projects-and-private-state-native034).
Native0.3.3 retains its [versioned Bot guide](native-participant-quickstart-0.3.3.md)
and [connect guide](participant-connect-0.3.3.md). Registry confirmation is a local
OS-owner operation, not a Workspace Owner approval or a permission bypass.

- [Workspace members, shared names and receiving status](workspace-members.md).

- [Member availability](member-availability.md): shared work-acceptance intent,
  membership-generation CAS, expiry and original-operation recovery.
