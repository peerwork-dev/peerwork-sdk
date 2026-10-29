# Fixed tools for ordinary Agents

Use [`peerwork-agent`](../bindings/agent-tools/README.md) for ordinary protocol
participation. Configure an existing identity, space, package and role once;
then send, reply, inspect, act, observe and recover through fixed commands.
The SDK is the internal cryptographic/recovery client and remains available for
custom application integrations. Ordinary Agents should not generate temporary
SDK scripts or handcraft HTTP signatures to communicate.

Agent tools 0.1.0 is versioned independently and uses the published SDK 0.2.16.
No native SDK rebuild, service restart or new protocol action is introduced by
this tool release. Send/reply mappings select actual declared protocol tools;
an alias observes a participant's receipt in the existing shared instance and
does not create a private direct-message channel. Follow the package guide for
setup, limits, original-operation recovery and exact availability.
