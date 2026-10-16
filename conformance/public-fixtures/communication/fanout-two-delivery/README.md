# fanout-two-delivery

Fixed fanout of two independently invoked artifact exchanges and all-of-two gather. The same executable exchange package is imported twice. Each branch has its own durable timeout/cancellation; no automatic dispatch or cascading cancellation is claimed. The aggregate output can be consumed by a larger composition.

Declarative protocol-source.v2 package. Imports are pinned by package digest; installation grants remain explicit. Actions run only when an authorized participant invokes them. No model hooks, network side effects, automatic wakeups, scheduling or external effect rollback are provided. Cancellation and timeout are durable protocol dispositions. Time guards use the runtime evaluation clock.

Source attribution: project-maintained communication components and the unchanged wiki-draft-component/wiki-review-component where imported.
