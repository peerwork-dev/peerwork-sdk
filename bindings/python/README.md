# Python bindings and historical command recovery

Current program integration uses the native Participant API, with embedded or
resident ownership. Ordinary Agents use loaded `peerwork_*` tools. Programs need
no Agent host or mandatory daemon; Python is not a native client dependency.
See the [current SDK guide](../../README.md) and [existing-client attachment](../../docs/existing-client-tools.md).

These Python sources retain low-level Kernel/verification primitives and
compatibility views for existing integrations. They do not define a second
recommended setup or durable business lifecycle. Source availability does not
prove current binary-wheel publication; consult the exact release assets.

`KernelClient` retains signing, E2EE, verification and original raw command IDs.
Use `resume_structure_intent` for uncertain original commands. Do not substitute
a Participant ID, replacement identity or new journal. Stateless protocol
helpers keep their explicit saved binding and prepared wire-input semantics;
ordinary actions use the Participant workflow.

Existing Context handles retain inspection and original-ID recovery. New Context
binding and business/access/key/publication execution return the native
retirement error without submission. See [Context recovery](../../docs/backend-structure-context-candidate.md).
Legacy Secure online execution remains retired; offline cryptographic work and
explicit archive conversion remain separate intentions.
