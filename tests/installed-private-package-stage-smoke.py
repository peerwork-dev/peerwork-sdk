"""Installed native PRIVATE package stage recovery; STAGED is not installed."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
expected_stage_hash = os.environ["PEERWORK_TEST_STAGE_SOURCE_SHA256"]
assert hashlib.sha256((SOURCE / "crates/runtime/src/secure_private_install.rs").read_bytes()).hexdigest() == expected_stage_hash
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def node_stages(config, workspace_id):
    env = dict(os.environ, PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_WORKSPACE=workspace_id, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE)
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  console.log(JSON.stringify(await owner.privatePackageStager(process.env.PEERWORK_TEST_WORKSPACE).stages()));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-1800:]
    return json.loads(result.stdout)


def stage_without_returning_id(origin, owner_dir, workspace_id, material_json, root_digest, protocol_digest):
    env = dict(os.environ, PEERWORK_TEST_ORIGIN=origin, PEERWORK_TEST_OWNER_DIR=str(owner_dir),
        PEERWORK_TEST_WORKSPACE=workspace_id, PEERWORK_TEST_MATERIAL=material_json,
        PEERWORK_TEST_ROOT_DIGEST=root_digest, PEERWORK_TEST_PROTOCOL_DIGEST=protocol_digest)
    code = r'''
import json, os, peerwork
owner=peerwork.SecureOwnerWorkspaceClient(os.environ['PEERWORK_TEST_ORIGIN'],
    os.environ['PEERWORK_TEST_OWNER_DIR'], allow_loopback_http=True)
result=owner.private_package_stager(os.environ['PEERWORK_TEST_WORKSPACE']).stage(
    os.environ['PEERWORK_TEST_MATERIAL'],
    expected_root_package_digest=os.environ['PEERWORK_TEST_ROOT_DIGEST'],
    expected_protocol_digest=os.environ['PEERWORK_TEST_PROTOCOL_DIGEST'])
# Intentional caller-delivery barrier: the generated stage/command IDs are
# withheld from the supervising process after the native operation returns.
print(json.dumps({key:result[key] for key in ('status','root_package_digest','protocol_digest','part_count')}))
'''
    result = subprocess.run([sys.executable, "-c", code], env=env,
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-1800:]
    assert "stage_id" not in result.stdout and "command_id" not in result.stdout
    return json.loads(result.stdout)


def cli(verb, config_file, workspace_id, stage_id=None):
    args = [CLI, "secure", verb, str(config_file), workspace_id]
    if stage_id is not None:
        args.append(stage_id)
    result = subprocess.run(args, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (verb, result.stderr[-1800:])
    return json.loads(result.stdout)


def post(origin, route):
    with urllib.request.urlopen(urllib.request.Request(origin + route, data=b"{}", method="POST"), timeout=10) as response:
        return json.load(response)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)


server_env = dict(os.environ, PEERWORK_TEST_STATE=str(STATE), PEERWORK_TEST_FIRST_POST_MODE="normal")
server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=server_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    owner_dir = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    prepared = owner.prepare("Installed PRIVATE stage", "PRIVATE", structured=True)
    assert prepared["status"] == "PENDING"
    created = owner.resume(prepared["command_id"])
    assert created["status"] == "CREATED" and created["visibility"] == "PRIVATE"
    workspace_id = created["workspace_id"]
    assert owner.read(workspace_id)["sequence"] == 1
    vector_name = os.environ.get("PEERWORK_TEST_VECTOR", "public-package-vectors.json")
    assert vector_name in {"public-package-vectors.json", "official-proposal-task-composition.json"}
    vector = json.loads((SOURCE / "conformance" / vector_name).read_text())
    expected_part_count = int(os.environ.get("PEERWORK_TEST_EXPECTED_PART_COUNT", "1"))
    material_json = json.dumps({"v": 1, "closure": vector["closure"], "bindings": {}},
                               separators=(",", ":"))
    root_digest = vector["closure"]["root_package_digest"]
    protocol_digest = vector["protocol_digest"]
    owner_config = dict(origin=origin, stateDir=str(owner_dir), allowLoopbackHttp=True)
    owner_config_file = STATE / "owner.json"
    owner_config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(owner_dir),
                                                 allow_loopback_http=True)))
    before = counts(origin)["commits"]
    post(origin, "__test/drop-next-post")
    # Simulate a dropped caller result: later clients learn this generated ID only
    # from their public protected stages() API, not a test-read of internal state.
    first = stage_without_returning_id(origin, owner_dir, workspace_id, material_json,
                                       root_digest, protocol_digest)
    assert first["status"] == "PENDING"
    assert first["part_count"] == expected_part_count
    assert first["root_package_digest"] == root_digest
    assert first["protocol_digest"] == protocol_digest
    after_apply = counts(origin)["commits"]
    assert after_apply == before + 1
    del owner
    recovered = node_stages(owner_config, workspace_id)
    assert len(recovered) == 1
    stage_id = recovered[0]["stage_id"]
    assert recovered[0]["root_package_digest"] == root_digest
    assert recovered[0]["protocol_digest"] == protocol_digest
    assert recovered[0]["source_id"]
    assert recovered[0]["saved_steps"] >= 1
    next_result = cli("owner-private-stage-continue", owner_config_file, workspace_id, stage_id)
    for _ in range(first["part_count"] + 1):
        if next_result["status"] == "STAGED":
            break
        next_result = cli("owner-private-stage-continue", owner_config_file, workspace_id, stage_id)
    assert next_result["status"] == "STAGED"
    assert next_result["stage_id"] == stage_id
    assert next_result["root_package_digest"] == root_digest
    assert next_result["protocol_digest"] == protocol_digest
    assert next_result["applied_parts"] == next_result["part_count"]
    assert next_result["part_count"] == expected_part_count
    assert counts(origin)["commits"] == before + next_result["part_count"]
    repeated = cli("owner-private-stage-continue", owner_config_file, workspace_id, stage_id)
    assert repeated == next_result
    assert counts(origin)["commits"] == before + next_result["part_count"]
    server.terminate()
    server.wait(timeout=5)
    offline_node = node_stages(owner_config, workspace_id)
    offline_cli = cli("owner-private-stage-list", owner_config_file, workspace_id)
    reopened = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    offline_python = reopened.private_package_stager(workspace_id).stages()
    assert offline_node == offline_cli == offline_python
    assert len(offline_python) == 1 and offline_python[0]["locally_verified_complete"] is True
    assert offline_python[0]["stage_id"] == stage_id
    print(json.dumps(dict(status="PASS", workspace_id=workspace_id, stage_id=stage_id,
        source_id=next_result["source_id"], root_package_digest=root_digest,
        protocol_digest=protocol_digest, vector=vector_name,
        part_count=next_result["part_count"],
        final_sequence=before + next_result["part_count"], local_offline_list=True,
        installed=False)))
finally:
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
