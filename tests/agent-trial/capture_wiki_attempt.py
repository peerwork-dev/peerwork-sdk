#!/usr/bin/env python3
"""Run and preserve one approved natural-task capture; setup is separate."""
import hashlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from threading import Thread

if len(sys.argv) != 3:
    raise SystemExit("usage: capture_wiki_attempt.py READY_TASK_DIRECTORY CODEX_EXECUTABLE")
task = Path(sys.argv[1]).resolve(strict=True)
actor, observer, operator = task / "actor", task / "observer", task / "operator"
codex = Path(sys.argv[2]).resolve(strict=True)
prompt = Path(__file__).with_name("WIKI_PROMPT.txt")
assert task.is_dir() and actor.is_dir() and observer.is_dir() and operator.is_dir()
assert codex.is_file() and os.access(codex, os.X_OK)
fixture = json.loads((observer / "fixture.json").read_text())
assert fixture.get("state") == "READY" and fixture.get("state_leaf_absent") is True
assert not (actor / "native-state").exists()
assert "PEERWORK_HTTP_PROXY" not in os.environ
assert hashlib.sha256((actor / "peerwork").read_bytes()).hexdigest() == fixture["cli_sha256"] == "d41590a8becd0140f1a84fdcffff2eaf75e3b7fd5d237dfb79400d61d4fc605e"
assert (actor / "ENVIRONMENT.json").is_file() and (actor / "selected-source/protocol.source.json").is_file()
inventory = json.loads(subprocess.check_output([str(codex), "mcp", "list", "--json", "-c", "mcp_servers={}"], text=True))
assert inventory == []
attempt = observer / "agent-attempt-1"
attempt.mkdir(mode=0o700, exist_ok=False)
for name, path in (("prompt.txt", prompt),):
    (attempt / name).write_bytes(path.read_bytes()); (attempt / name).chmod(0o600)
policy = [
    'approval_policy="never"', 'default_permissions="trial"',
    'permissions.trial.extends=":workspace"', 'permissions.trial.network.enabled=true',
    'permissions.trial.network.domains={"127.0.0.1"="allow"}',
    'permissions.trial.network.allow_local_binding=false',
    'permissions.trial.network.allow_upstream_proxy=false',
    'features.network_proxy.enabled=true', 'features.network_proxy.domains={"127.0.0.1"="allow"}',
    'features.network_proxy.allow_local_binding=false', 'features.network_proxy.allow_upstream_proxy=false',
    'features.network_proxy.enable_socks5=false', 'features.network_proxy.enable_socks5_udp=false',
    'web_search="disabled"', 'tools.web_search=false', 'apps._default.enabled=false',
    'features.multi_agent=false', 'mcp_servers={}',
]
argv = [str(codex), "exec", "--strict-config", "--model", "gpt-6-luna", "--ephemeral",
        "--ignore-user-config", "--json", "--skip-git-repo-check", "--cd", str(actor)]
for setting in policy: argv.extend(("-c", setting))
argv.append("-")
invocation = {"argv":argv, "cwd":str(actor), "deadline_seconds":480,
    "prompt_sha256":hashlib.sha256((attempt/"prompt.txt").read_bytes()).hexdigest(),
    "codex_sha256":hashlib.sha256(codex.read_bytes()).hexdigest(),
    "mcp_count":len(inventory), "runner_preselected_sdk_proxy":False,
    "scope":"one synthetic fresh PRIVATE wiki workflow; raw evidence operator-only"}
(attempt/"invocation.json").write_text(json.dumps(invocation,indent=2)+"\n"); (attempt/"invocation.json").chmod(0o600)
started = datetime.now(timezone.utc).isoformat(); start_ns = time.monotonic_ns()
receive_errors=[]; input_error=None; expired=False
with (attempt/"tool-events.jsonl").open("wb") as events, (attempt/"event-times.jsonl").open("w") as times, (attempt/"stderr.log").open("wb") as err:
    process=subprocess.Popen(argv,cwd=actor,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=err,start_new_session=True)
    def receive():
        try:
            for i,line in enumerate(process.stdout,1):
                events.write(line)
                times.write(json.dumps({"line":i,"received_utc":datetime.now(timezone.utc).isoformat(),
                  "elapsed_ms":(time.monotonic_ns()-start_ns)//1_000_000,"sha256":hashlib.sha256(line).hexdigest()})+"\n")
        except Exception as error: receive_errors.append(type(error).__name__)
    thread=Thread(target=receive,daemon=True); thread.start()
    try:
        try: process.stdin.write((attempt/"prompt.txt").read_bytes())
        except BrokenPipeError: input_error="BrokenPipeError"
        finally:
            try: process.stdin.close()
            except BrokenPipeError: input_error="BrokenPipeError"
        process.wait(timeout=480)
    except subprocess.TimeoutExpired:
        expired=True; os.killpg(process.pid,signal.SIGTERM)
        try: process.wait(timeout=10)
        except subprocess.TimeoutExpired: os.killpg(process.pid,signal.SIGKILL); process.wait()
    thread.join(timeout=10)
    if thread.is_alive():
        try: os.killpg(process.pid,signal.SIGTERM)
        except ProcessLookupError: pass
        thread.join(timeout=5)
    stream_closed=not thread.is_alive()
for name in ("tool-events.jsonl","event-times.jsonl","stderr.log"):(attempt/name).chmod(0o600)
event_summary={"json_events":0,"invalid_lines":0,"commands_started":0,"commands_completed":0}
for line in (attempt/"tool-events.jsonl").read_text(errors="replace").splitlines():
    try: event=json.loads(line)
    except json.JSONDecodeError: event_summary["invalid_lines"]+=1; continue
    event_summary["json_events"]+=1
    if event.get("item",{}).get("type")=="command_execution":
        if event.get("type")=="item.started": event_summary["commands_started"]+=1
        elif event.get("type")=="item.completed": event_summary["commands_completed"]+=1
result={"started_utc":started,"finished_utc":datetime.now(timezone.utc).isoformat(),
  "exit_code":process.returncode,"deadline_expired":expired,"event_stream_closed":stream_closed,
  "input_write_error":input_error,"receive_errors":receive_errors,"event_summary":event_summary,
  "events_sha256":hashlib.sha256((attempt/"tool-events.jsonl").read_bytes()).hexdigest(),
  "event_times_sha256":hashlib.sha256((attempt/"event-times.jsonl").read_bytes()).hexdigest(),
  "stderr_sha256":hashlib.sha256((attempt/"stderr.log").read_bytes()).hexdigest(),
  "workflow_compliance":"UNASSESSED","business_correctness":"UNASSESSED"}
(attempt/"process.json").write_text(json.dumps(result,indent=2)+"\n"); (attempt/"process.json").chmod(0o600)
drop_path=operator/"wiki-drop.json"
drop=None
if drop_path.is_file(): drop=json.loads(drop_path.read_text())
db=Path(fixture["control_database"])
with sqlite3.connect(f"file:{db}?mode=ro",uri=True) as connection:
    rows=connection.execute("SELECT workspace_id,sequence,command_id,artifact FROM secure_commits ORDER BY rowid").fetchall()
    workspace_counts={}
    accepted_wiki=0
    for workspace,sequence,command,artifact in rows:
        workspace_counts[workspace]=workspace_counts.get(workspace,0)+1
        try: wire=json.loads(artifact)
        except (TypeError,json.JSONDecodeError): continue
        payload=wire.get("payload",{}) if isinstance(wire,dict) else {}
        if payload.get("action_id")=="wiki.create": accepted_wiki+=1
effects={"database_commit_rows":len(rows),"workspace_commit_counts":workspace_counts,
  "accepted_wiki_create_commits":accepted_wiki,"wiki_response_drop_observed":drop is not None,
  "wiki_drop_metadata":drop,"native_state_created":(actor/"native-state").exists(),
  "source":"operator read-only Control SQLite plus protected response-drop metadata; not a signed-read oracle"}
(attempt/"persisted-effects.json").write_text(json.dumps(effects,indent=2)+"\n"); (attempt/"persisted-effects.json").chmod(0o600)
print(json.dumps({"attempt":str(attempt),"exit_code":process.returncode,"deadline_expired":expired,
  "events_sha256":result["events_sha256"],"wiki_response_drop_observed":drop is not None,
  "accepted_wiki_create_commits":accepted_wiki}))
