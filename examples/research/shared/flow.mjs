// SPDX-License-Identifier: Apache-2.0
import { createHash } from "node:crypto";
export const sha = (text) => createHash("sha256").update(text).digest("hex");
export const tasks = [
  { id: "left", numbers: [2, 3] },
  { id: "right", numbers: [5, 7] },
];
export const scriptedArtifact = (task) =>
  JSON.stringify({
    task_id: task.id,
    value: task.numbers.reduce((a, b) => a + b, 0),
  });
export function verifyArtifact(text, task) {
  try {
    const result = JSON.parse(text);
    return (
      Object.keys(result).sort().join(",") === "task_id,value" &&
      result.task_id === task.id &&
      result.value === task.numbers.reduce((a, b) => a + b, 0)
    );
  } catch {
    return false;
  }
}
/** Same worker policy for both peers. Harness choices are outside protocol enforcement. */
export async function advanceWorker({
  recipe,
  actor,
  board,
  work,
  artifact,
  agent = async ({ task }) => scriptedArtifact(task),
  integrate = async () => {},
  findings = async () => [],
}) {
  const notes = await findings();
  for (let index = 0; index < work.length; index++) {
    const client = work[index],
      task = tasks[index],
      current = await client.read(),
      s = current.state,
      key = (part) =>
        `${recipe}/${actor}/${task.id}/${part}/${current.revision}`;
    if (s.work_state === "DONE") continue;
    if (
      s.work_state === "OPEN" &&
      (s.lease_holder === null ||
        s.lease_holder === actor ||
        Date.now() >= s.lease_expires)
    ) {
      let lease = s.lease_ref,
        revision = current.revision;
      if (s.lease_holder !== actor) {
        const attempt = s.lease_holder === null ? "work.claim" : "work.reclaim",
          r = await client.act(
            attempt,
            { ttl_ms: 600000 },
            key(attempt) +
              (attempt === "work.reclaim"
                ? "/" + Math.floor(Date.now() / 5000)
                : ""),
            { revision },
          );
        if (r.state !== "ACCEPTED") {
          if (r.state === "REJECTED") continue;
          return { waiting: true, code: r.code };
        }
        lease = r.state_snapshot.lease_ref;
        revision = r.revision;
      }
      const note = await artifact(
        `${task.id}-partial`,
        JSON.stringify({
          task_id: task.id,
          interface: "component result is {task_id,value}",
          observation: "A component can be reused before final integration.",
        }),
      );
      const published = await board.act(
        "finding.publish",
        { kind: "OBSERVED", subject: task.id },
        `${recipe}/${actor}/${task.id}/partial`,
        { revision: 1, artifact: note },
      );
      if (published.state !== "ACCEPTED") return { waiting: true };
      const output = await artifact(`${task.id}-result`, () =>
        agent({ task, peer_findings: notes, recipe }),
      );
      const r = await client.act(
        "work.submit",
        { claim_ref: lease, artifact_digest: output.sha256 },
        `${recipe}/${actor}/${task.id}/submit/${lease.record_id}`,
        { revision, refs: [lease], artifact: output },
      );
      return { waiting: r.state === "PENDING", code: r.code };
    }
    if (s.work_state === "SUBMITTED") {
      const selected = await client.record(s.result_ref),
        value = selected.structure.structure;
      if (value.author === actor) continue;
      const opened = selected.opened_contents.find(
        (x) => x.record_id === s.result_ref.record_id,
      );
      if (opened?.state !== "OPENED") throw Error("RESULT_BODY_NOT_READY");
      const passed =
          sha(opened.text) === value.artifact_digest &&
          verifyArtifact(opened.text, task),
        evidence = JSON.stringify({
          task_id: task.id,
          artifact_digest: value.artifact_digest,
          check: "synthetic-component-input-output",
          passed,
        });
      const report = await artifact(
        `${task.id}-review-${s.result_ref.record_id}`,
        evidence,
      );
      const r = await client.act(
        "review.record",
        {
          proposal_ref: s.result_ref,
          verdict: passed ? "PASS" : "FAIL",
          evidence_digest: sha(evidence),
        },
        key("review"),
        { revision: current.revision, refs: [s.result_ref], artifact: report },
      );
      return { waiting: r.state === "PENDING", code: r.code };
    }
    if (s.work_state === "REVIEWED") {
      const selected = await client.record(s.result_ref),
        text = selected.opened_contents.find(
          (x) => x.record_id === s.result_ref.record_id,
        )?.text;
      if (!verifyArtifact(text, task))
        throw Error("INTEGRATION_ARTIFACT_INVALID");
      await integrate({
        task,
        text,
        result_ref: s.result_ref,
        review_ref: s.review_ref,
      });
      const r = await client.act(
        "review.adopt",
        { review_ref: s.review_ref },
        key("adopt"),
        { revision: current.revision, refs: [s.review_ref] },
      );
      return { waiting: r.state === "PENDING", code: r.code };
    }
  }
  const snapshots = await Promise.all(work.map((c) => c.read()));
  if (snapshots.some((x) => x.state.work_state !== "DONE"))
    return { waiting: true };
  const components = [];
  for (let i = 0; i < work.length; i++) {
    const r = await work[i].record(snapshots[i].state.result_ref),
      text = r.opened_contents.find(
        (x) => x.record_id === snapshots[i].state.result_ref.record_id,
      )?.text;
    if (!verifyArtifact(text, tasks[i])) throw Error("CANDIDATE_INVALID");
    components.push(JSON.parse(text));
  }
  return {
    done: true,
    candidate: {
      components,
      total: components.reduce((n, x) => n + x.value, 0),
    },
    recipe,
  };
}
