"""Synthetic installed CLI workflow fixture; no production data or secrets.

The parent owns the real service and admitted member. This module preserves a
single applied-but-unanswered task, then waits for one frozen Agent trial.
"""
import json
import os
from pathlib import Path
import time

import peerwork


def hold(*, state, origin, workspace_id, recipient_dir, actor_id, owner_pins,
         instance_id, post, source, cli, node, node_package):
    trial = state / "agent-trial"
    trial.mkdir(mode=0o700)

    def write(path, value):
        with path.open("x", encoding="utf-8") as stream:
            path.chmod(0o600)
            json.dump(value, stream)
        return path

    member_profile = write(trial / "member-profile.json", dict(
        origin=origin, state_dir=str(recipient_dir),
        identity_path=str(recipient_dir / "identity.state"),
        workspace_id=workspace_id, owner_actor_id=owner_pins["actor_id"],
        owner_key_id=owner_pins["key_id"], allow_loopback_http=True))
    profile = trial / "context.json"
    service = "installed-agent-workflow-trial"
    ctx = peerwork.bind_context(profile=profile, expected_actor=actor_id,
        expected_service=service, workspace_profiles=[member_profile])

    entry_body = """Workspace-local entry protocol for this synthetic trial.

Use the selected identity/service/context given by the caller. Read this exact
entry document and the installed protocol/action sources through verified SDK
discovery/description. This workspace declares no universal master workflow.

Before creating work, inspect saved operations. The caller's logical operation
already exists: recover its original result and report its exact command ID,
record reference and member authorship. Do not submit a replacement action or
create an additional document, even if an earlier reply was lost.

Synchronize the native verified-action-receipts source. Receive using consumer
trial-worker and filter version trial-v1; inspect each delivered receipt and
acknowledge local delivery. Find the recovered task's command-bound receipt.
An acknowledgement is not business-task completion. Drain currently queued
receipts, then use one native receive with wait_ms=500. When it returns the
deadline, persist a handoff with the context fingerprint, consumer ID, filter
version, wait status and continuation. Do not run an Agent polling loop.

Use the provided audited installed CLI for this trial. Ordinary request JSON
files and a final result JSON are allowed in the trial directory. Complete all
work without source checkout scripts, copying keys or choosing a new identity.
"""
    entry_intent = dict(kind="protocol.action", instance_id=instance_id,
        action_id="wiki.create", values=dict(title="Trial entry protocol", body=entry_body), refs=[])
    ctx.operate(workspace_id, entry_intent, "trial-entry-document")
    entry = ctx.recover(workspace_id, operation_id="trial-entry-document")
    assert entry["status"] == "verified"
    entry_ref = entry["refs"][0]

    operation_id = "trial-original-task"
    task_intent = dict(kind="protocol.action", instance_id=instance_id,
        action_id="wiki.create", values=dict(title="Recovered trial report",
        body="Recover this original accepted result; do not create another report."), refs=[])
    post(origin, "__test/drop-next-post")
    pending = ctx.operate(workspace_id, task_intent, operation_id)
    assert pending["status"] == "pending"
    command_id = pending["result"]["command_id"]

    audit = trial / "cli-audit.jsonl"
    write(audit, [])
    audit.write_text("")
    wrapper = trial / "peerwork"
    # Capture the actual installed CLI invocation and response. Redact optional
    # approval secrets even though this trial has no browser approval task.
    wrapper_source = '''#!/usr/bin/env python3
import hashlib,json,os,pathlib,subprocess,sys,time
CLI=__CLI__
AUDIT=pathlib.Path(__AUDIT__)
def clean(v):
 if isinstance(v,dict):return {k:('<redacted>' if k in ('approval_code','one_time_code') else clean(x)) for k,x in v.items()}
 if isinstance(v,list):return [clean(x) for x in v]
 if isinstance(v,str) and v.startswith('peerwork-secure-code:'):return '<redacted>'
 return v
args=sys.argv[1:];start=time.time();request=None
if args:
 p=pathlib.Path(args[-1])
 if p.is_file() and p.suffix=='.json':
  try:request=clean(json.loads(p.read_text()))
  except (ValueError,OSError):pass
r=subprocess.run([CLI,*args],capture_output=True)
try:result=clean(json.loads(r.stdout))
except (ValueError,UnicodeDecodeError):result={'sha256':hashlib.sha256(r.stdout).hexdigest()}
record={'started_at':start,'elapsed_seconds':time.time()-start,'args':args,'request':request,'exit_code':r.returncode,'result':result,'stderr':r.stderr.decode('utf8','replace')[:2000]}
with AUDIT.open('a') as f:f.write(json.dumps(record)+'\\n')
sys.stdout.buffer.write(r.stdout);sys.stderr.buffer.write(r.stderr);sys.exit(r.returncode)
'''.replace("__CLI__", repr(str(cli))).replace("__AUDIT__", repr(str(audit)))
    wrapper.write_text(wrapper_source)
    wrapper.chmod(0o700)

    ready = dict(schema="peerwork.installed-agent-trial.v1", status="READY",
        cli=str(wrapper), actual_cli=str(cli), cwd=str(trial), profile=str(profile),
        expected_actor=actor_id, expected_service=service, workspace_id=workspace_id,
        entry_ref=entry_ref, operation_id=operation_id, expected_command_id=command_id,
        instance_id=instance_id, consumer_id="trial-worker", filter_version="trial-v1",
        audit_path=str(audit), result_path=str(trial / "agent-result.json"),
        handoff_path=str(trial / "handoff.json"), origin=origin,
        fixture_lifetime_seconds=600)
    write(trial / "ready.json", ready)
    print(json.dumps(dict(status="AGENT_TRIAL_READY", ready_path=str(trial / "ready.json"))), flush=True)
    deadline = time.monotonic() + 600
    while time.monotonic() < deadline and not (trial / "STOP").exists():
        time.sleep(0.2)
    write(trial / "fixture-stop.json", dict(status="STOPPED",
        reason="requested" if (trial / "STOP").exists() else "deadline"))
