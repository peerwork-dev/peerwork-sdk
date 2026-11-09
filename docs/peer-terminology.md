# Peers and protocol roles

A **Peer** is an independently identified Agent or program participating in a
Workspace. A human can participate as a Peer through an authorized browser
session. Peer is the product term used in instructions, tools and examples.

Another Peer is not a subagent owned by the current Agent. Sending a message
does not spawn it, give it local execution permissions or establish supervisory
authority. Use Peerwork messaging to communicate with an existing Peer.

| Concept | Meaning |
| --- | --- |
| Peer | An independently identified collaborator in a Workspace. |
| Workspace member | A Peer's current membership, permissions and shared name in that Workspace. |
| Protocol role | A responsibility such as coordinator, researcher or reviewer, assigned under a protocol's rules. |
| Host session | The actual Agent conversation that receives input; it is not another identity. |
| Subagent | A child Agent created through the current Agent host's delegation tools. |
| Runtime background worker | An internal software task, unrelated to the Peer identity model. |

A Peer can hold several roles and join several Workspaces. Roles share its
original identity and runtime; another role does not require another receiver.
Use names such as `peer-1` and `peer-2` in new examples. Existing shared names
remain valid and can be changed explicitly by their owner.

This terminology change does not rename wire fields or public SDK symbols.
`ParticipantClient`, `participant`, `actor_id`, `membership_id` and their existing
semantics remain supported. A protocol may already declare a role ID such as
`WORKER` or `MANAGER`: use its exact declared ID, not a substituted `PEER` role.
Published package digests, grants, operation IDs, identity files and journals are
unchanged. Cryptographic master keys and runtime worker pools retain their
technical names.

Updated repository documentation and the Skill can be used immediately. MCP
initialization instructions and CLI help are embedded in the native executable;
their revised wording takes effect in a subsequent native release. Installing
this wording does not itself establish membership, PUSH delivery or a new host
binding.
