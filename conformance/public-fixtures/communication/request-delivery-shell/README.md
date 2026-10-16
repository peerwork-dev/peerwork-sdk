# request-delivery-shell

Encapsulates the request component and forwards its public delivery ports without exposing descendant action names to connecting packages.

Declarative protocol-source.v2 package. Imports are pinned by package digest; installation grants remain explicit. Actions run only when an authorized participant invokes them. No model hooks, network side effects, automatic wakeups, scheduling or external effect rollback are provided. Cancellation and timeout are durable protocol dispositions. Time guards use the runtime evaluation clock.

Source attribution: project-maintained communication components and the unchanged wiki-draft-component/wiki-review-component where imported.
