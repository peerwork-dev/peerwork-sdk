# Business event replay and current presence

For `structure.events.read`, clients supporting presence-history compaction use
`{"profile":"backend-structure-v1","presence_replay":"SNAPSHOT_V1",...}`.
Use the modern native `ParticipantClient::request` entry. Its receipt verifier
checks the reset envelope and the nested authorized member-directory snapshot.
A legacy request crossing compacted presence history receives
`PRESENCE_REPLAY_RESET_REQUIRED`; it must explicitly adopt the snapshot contract.

A `presence_reset` affects only `communication.member.presence.changed` history.
It contains an authorized COLLABORATION member-directory page, the pruned
presence boundary, and `snapshot_checkpoint` G. Apply the directory page and
follow `snapshot_request`, then subsequent directory `next_cursor` pages, in the
same Workspace. Directory visibility and membership rules still apply. If the
directory cursor becomes invalid, obtain a new authorized snapshot rather than
pretending a partial directory is complete.

Keep two independent progress values:

- Business events use the outer result's `next_cursor` while pages remain, then
  its `checkpoint` as the next `after_sequence`. Process every returned event
  with its verified source before advancing that progress.
- Presence reconciliation uses G after the snapshot is fully applied. Supply
  `presence_checkpoint: G` alongside `presence_replay: "SNAPSHOT_V1"` on later
  event reads. A business pagination frontier can be older than G.

The reset's `resume.after_sequence` describes presence reconciliation only.
Replacing a business cursor with it could skip retained business events.
`peerwork_runtime::event_replay::next_body_after_snapshot(original_body, result)`
builds the next business body while retaining the separate presence checkpoint.
Call it only after applying the event page and completing any directory snapshot;
it does not fetch pages, save progress, create another receiver or change
operation IDs. Pass only the verified result from the selected client's request.
The helper preserves the original request filters and page limit.

The signed outer receipt binds snapshot scope, reset kind, checkpoint and
continuation. Current presence is a service observation, not an authored
business action or proof of model response. Business history and pending message
custody are unaffected by the presence reset.
