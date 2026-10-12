# Peerwork Proposal and Adoption

Reusable proposal and independent-adoption component. Adoption requires an authenticated actor different from the author recorded from auth.actorId and an exact candidate reference equal to the pinned state reference. Role conflict declarations additionally constrain role grants but do not implement the authorship predicate.

This official protocol package is derived from the project-maintained source at `src/workspace-presets.ts`. Its `protocol.source.json` contains the complete runtime manifest, including action rules, record schemas, role declarations, constraints, and state defaults.

The package is licensed under Apache-2.0; the complete license text is in `LICENSE`. The fixture suite includes at least one authorized interaction and one unauthenticated rejection, executed by the shared portable evaluator. Package attribution identifies source maintainers only; publication authority is the separately authenticated catalog publisher.

This is protocol content for the workspace kernel. It does not include workspace instances, role grants, user bindings, or private protocol agreements.
