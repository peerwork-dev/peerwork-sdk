# artifact-request-delivery

Executable artifact exchange: binds the reusable request component to the existing Wiki draft component. The result is the actual wiki.revision, never the delivery receipt. Output is unavailable if the draft changes after delivery; start a fresh exchange for another result.

Declarative protocol-source.v2 package. Imports are pinned by package digest; installation grants remain explicit. Actions run only when an authorized participant invokes them. No model hooks, network side effects, automatic wakeups, scheduling or external effect rollback are provided. Cancellation and timeout are durable protocol dispositions. Time guards use the runtime evaluation clock.

Source attribution: project-maintained communication components and the unchanged wiki-draft-component/wiki-review-component where imported.
