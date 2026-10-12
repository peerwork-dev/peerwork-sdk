import asyncio
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import threading
import time
import urllib.request

import peerwork

ROOT = Path(__file__).resolve().parents[1]
NODE = os.environ["PEERWORK_TEST_NODE"]
REFERENCE = os.environ["PEERWORK_REFERENCE_ROOT"]
NATIVE_ADDON = Path(os.environ["PEERWORK_TEST_NODE_ADDON"])
WHEEL = Path(os.environ["PEERWORK_TEST_WHEEL"])
CLI = Path(os.environ["PEERWORK_TEST_CLI"])
SOURCE_COMMIT = os.environ["PEERWORK_TEST_SOURCE_COMMIT"]
assert subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
).strip() == SOURCE_COMMIT, "SDK source checkout differs from artifact pin"
started = time.monotonic()
stages = []


def mark(stage):
    stages.append({"stage": stage, "elapsed_ms": round((time.monotonic() - started) * 1000)})


def counts(origin):
    with urllib.request.urlopen(origin + "__test/counts", timeout=2) as response:
        return json.load(response)


def wait_applied(origin):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        if counts(origin)["commands"] == 1:
            return
        time.sleep(0.02)
    raise AssertionError("real service did not commit before cancellation")


def command(info, fill):
    now = int(time.time() * 1000)
    return dict(
        v=1, audience="reference-kernel",
        command_id=base64.urlsafe_b64encode(bytes([fill]) * 32).decode().rstrip("="),
        actor_id=info["actor_id"],
        authority=hashlib.sha256(info["actor_id"].encode()).hexdigest(),
        method="POST", path="/api/workspace/v1/commands",
        workspace_id=None, instance_id=None, protocol_digest=None,
        action_id="workspace.create", expected_workspace_revision=None,
        expected_instance_revision=None, exact_input_refs=[],
        body={"name": f"cancel {fill}", "visibility": "PUBLIC"},
        issued_at=now, expires_at=now + 600_000,
    )


def server_for(state):
    env = os.environ.copy()
    env.update(PEERWORK_REFERENCE_ROOT=REFERENCE, PEERWORK_TEST_STATE=str(state),
               PEERWORK_TEST_FIRST_POST_MODE="delay",
               PEERWORK_TEST_FIRST_POST_DELAY_MS="5000")
    server = subprocess.Popen(
        [NODE, str(ROOT / "tests/reference-kernel-server.mjs")],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, text=True,
    )
    line = server.stdout.readline()
    assert line, "real service did not start"
    return server, json.loads(line)["origin"]


def state_for(label):
    directory = tempfile.TemporaryDirectory(prefix="peerwork-cancel-" + label + "-")
    path = Path(directory.name)
    path.chmod(0o700)
    return directory, path


mark("installed_python_import")


async def repeated_python_cancel_drain():
    entered = threading.Event()
    release = threading.Event()
    exited = threading.Event()

    class SlowLocalCall(peerwork.KernelClient):
        def _call(self, *args, **kwargs):
            entered.set()
            try:
                assert release.wait(timeout=3), "worker was never released"
                return {}
            finally:
                exited.set()

    client = SlowLocalCall("https://unused.invalid/", "unused", "unused")
    task = asyncio.create_task(client.open_async())
    try:
        assert await asyncio.to_thread(entered.wait, 2), "worker did not start"
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done(), "second cancellation abandoned the live worker"
    finally:
        release.set()
    try:
        await asyncio.wait_for(task, timeout=2)
        raise AssertionError("repeated cancellation returned success")
    except asyncio.CancelledError:
        pass
    assert exited.is_set(), "cancelled wrapper returned before native worker exited"


asyncio.run(repeated_python_cancel_drain())
mark("python_repeated_cancel_drained")

directory, state = state_for("python")
server, origin = server_for(state)
try:
    identity_path = state / "identity.state"
    journal_path = state / "journal.sqlite"
    info = peerwork.create_identity(str(identity_path))
    client = peerwork.KernelClient(origin, str(journal_path), str(identity_path),
                                   allow_loopback_http=True)
    value = command(info, 93)
    command_id = value["command_id"]
    client.prepare(value)

    async def python_cancel():
        worker = asyncio.create_task(client.submit_saved_async(command_id))
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and counts(origin)["commands"] != 1:
            await asyncio.sleep(0.02)
        assert counts(origin)["commands"] == 1
        worker.cancel()
        try:
            await asyncio.wait_for(worker, timeout=2)
            raise AssertionError("cancelled Python submit returned success")
        except asyncio.CancelledError:
            pass

    asyncio.run(python_cancel())
    mark("python_inflight_cancel_drained")
    assert client.status(command_id)["state"] == "PENDING"
    assert client.submit_saved(command_id)["command_id"] == command_id
    assert counts(origin) == {
        "commands": 1, "workspaces": 1, "protocols": 0,
        "workspace_revision": 1,
    }
    mark("python_exact_retry_verified")
finally:
    server.terminate()
    server.wait(timeout=5)
    directory.cleanup()

directory, state = state_for("node")
server, origin = server_for(state)
try:
    identity_path = state / "identity.state"
    journal_path = state / "journal.sqlite"
    peerwork.create_identity(str(identity_path))
    node_code = r'''
const sdk=require('./.build-artifacts/node-consumer/index.cjs');
const crypto=require('crypto');
(async()=>{
  const [origin,journal,identity]=process.argv.slice(1);
  const client=await sdk.openKernel({origin,journalPath:journal,identityPath:identity,allowLoopbackHttp:true});
  const id=Buffer.alloc(32,94).toString('base64url'),now=Date.now();
  const command={v:1,audience:'reference-kernel',command_id:id,actor_id:client.actor_id,
    authority:crypto.createHash('sha256').update(client.actor_id).digest('hex'),method:'POST',
    path:'/api/workspace/v1/commands',workspace_id:null,instance_id:null,protocol_digest:null,
    action_id:'workspace.create',expected_workspace_revision:null,expected_instance_revision:null,
    exact_input_refs:[],body:{name:'cancel 94',visibility:'PUBLIC'},issued_at:now,expires_at:now+600000};
  await client.prepare(command);
  const controller=new AbortController();
  const inFlight=client.submitSaved(id,{signal:controller.signal});
  const deadline=Date.now()+3000;
  while(Date.now()<deadline){
    const result=await (await fetch(origin+'__test/counts')).json();
    if(result.commands===1) break;
    await new Promise(resolve=>setTimeout(resolve,20));
  }
  if((await (await fetch(origin+'__test/counts')).json()).commands!==1) throw Error('service did not commit');
  controller.abort();
  try{await inFlight;throw Error('aborted Node submit returned success')}
  catch(error){if(!String(error).includes('uncertain')) throw error}
  if((await client.status(id)).state!=='PENDING') throw Error('aborted Node row not pending');
  if((await client.submitSaved(id)).command_id!==id) throw Error('Node retry failed');
  const totals=await (await fetch(origin+'__test/counts')).json();
  if(totals.commands!==1||totals.workspaces!==1||totals.protocols!==0||totals.workspace_revision!==1)
    throw Error('duplicate Node effect');
  console.log('Node in-flight AbortSignal/retry passed');
})().catch(error=>{console.error(error);process.exitCode=1});
'''
    subprocess.run([NODE, "-e", node_code, origin, str(journal_path), str(identity_path)],
                   cwd=ROOT, check=True, timeout=30)
    mark("node_inflight_abort_and_retry")
finally:
    server.terminate()
    server.wait(timeout=5)
    directory.cleanup()

directory, state = state_for("cli")
server, origin = server_for(state)
try:
    identity_path = state / "identity.state"
    journal_path = state / "journal.sqlite"
    info = peerwork.create_identity(str(identity_path))
    value = command(info, 95)
    command_id = value["command_id"]
    client = peerwork.KernelClient(origin, str(journal_path), str(identity_path),
                                   allow_loopback_http=True)
    client.prepare(value)
    cli = str(CLI)
    args = [cli, "kernel", "submit", origin, str(journal_path),
            str(identity_path), command_id, "--allow-loopback-http"]
    in_flight = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wait_applied(origin)
    in_flight.send_signal(signal.SIGINT)
    stdout, stderr = in_flight.communicate(timeout=3)
    assert in_flight.returncode == 130, (in_flight.returncode, stdout, stderr)
    assert json.loads(stderr)["code"] == "INTERRUPTED"
    assert client.status(command_id)["state"] == "PENDING"
    completed = subprocess.run(args, capture_output=True, check=True, timeout=15)
    assert json.loads(completed.stdout)["command_id"] == command_id
    assert counts(origin) == {
        "commands": 1, "workspaces": 1, "protocols": 0,
        "workspace_revision": 1,
    }
    mark("cli_sigint_pending_and_retry")
finally:
    server.terminate()
    server.wait(timeout=5)
    directory.cleanup()

artifacts = [
    WHEEL, NATIVE_ADDON, CLI,
]
evidence = {
    "kind": "scripted fresh synthetic real-service cancellation business-path evidence",
    "agent_workflow_compliance": "unverified; this script is not an Agent usability run",
    "source_commit": SOURCE_COMMIT,
    "artifacts_sha256": {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in artifacts},
    "stages": stages,
    "assertions": [
        "Python cancellation during committed delayed POST drained native worker and retained pending row",
        "Node AbortSignal during committed delayed POST retained pending row",
        "CLI SIGINT during committed delayed POST exited 130 and retained pending row",
        "Each exact saved retry verified accepted result with one real server command/workspace",
    ],
}
(ROOT / ".build-artifacts/cancellation-service-evidence.json").write_text(
    json.dumps(evidence, indent=2) + "\n"
)
print("Python/Node/CLI in-flight cancellation and exact retry passed")
