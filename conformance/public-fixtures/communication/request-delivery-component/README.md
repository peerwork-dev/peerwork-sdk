# request-delivery-component

Single immutable request, explicit recipient ACK, exact result delivery, requester cancellation and runtime-clock timeout. Requester and responder must differ. One exchange per instance; delivery ports must be connected to an artifact source.

Declarative protocol-source.v2 package. Imports are pinned by package digest; installation grants remain explicit. Actions run only when an authorized participant invokes them. No model hooks, network side effects, automatic wakeups, scheduling or external effect rollback are provided. Cancellation and timeout are durable protocol dispositions. Time guards use the runtime evaluation clock.

Source attribution: project-maintained communication components and the unchanged wiki-draft-component/wiki-review-component where imported.
