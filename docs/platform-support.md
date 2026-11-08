# Platform support

The published native target is Linux x86_64 GNU with glibc2.28+ and the system
C++ runtime imports listed in the release's qualification metadata. There is no
Node/Python dependency for the native executable. Use only actual assets from the
[current release](https://github.com/peerwork-dev/peerwork-sdk/releases/latest).

Source portability does not establish a qualified binary for another platform.
Program embedding, Agent host integration, service capabilities and receiving
readiness have separate requirements. See [distribution](native-distribution.md),
[quickstart](native-participant-quickstart.md) and [host setup](native-session-connectors.md).
