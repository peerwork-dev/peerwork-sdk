"""Installed native PRIVATE stage→install→encrypted action, with saved-ID recovery.

This is scripted API evidence. It uses a one-part official package vector and
does not test natural Agent workflow or nonempty PAGE continuation.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, variable in (
    ("crates/runtime/src/secure_private_install.rs", "PEERWORK_TEST_INSTALL_SOURCE_SHA256"),
    ("crates/core/src/secure_replay.rs", "PEERWORK_TEST_REPLAY_SOURCE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def post(origin, route):
    request = urllib.request.Request(origin + route, data=b"{}", method="POST")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.load(response)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)


def node_call(config, workspace_id, operation, **values):
    env = dict(os.environ, PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_WORKSPACE=workspace_id,
               PEERWORK_TEST_OPERATION=operation,
               PEERWORK_TEST_VALUES=json.dumps(values),
               PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE)
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const workspace = process.env.PEERWORK_TEST_WORKSPACE;
  const op = process.env.PEERWORK_TEST_OPERATION;
  const value = JSON.parse(process.env.PEERWORK_TEST_VALUES);
  let result;
  if (op === 'beginWithoutId') {
    result = await owner.privatePackageInstaller(workspace).begin(value.selection);
    result = {status: result.status, step_action_id: result.step_action_id,
      protocol_digest: result.protocol_digest, instance_id: result.instance_id};
  } else if (op === 'continueInstall') {
    result = await owner.privatePackageInstaller(workspace).continueInstall(value.beginId);
  } else if (op === 'installs') {
    result = await owner.privatePackageInstaller(workspace).installs();
  } else if (op === 'propose') {
    result = await owner.privateActions(workspace).submit('proposal.propose', value.instanceId,
      {title: value.title, body: value.body});
  } else throw new Error('unsupported test operation');
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error.code || error.message); process.exitCode = 1; });
'''
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-1600:]
    return json.loads(result.stdout)


def cli(verb, config_file, workspace_id, argument=None):
    command = [CLI, "secure", verb, str(config_file), workspace_id]
    if argument is not None:
        command.append(argument)
    result = subprocess.run(command, capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (verb, result.stderr[-1600:])
    return json.loads(result.stdout)


server_env = dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                  PEERWORK_TEST_FIRST_POST_MODE="normal")
server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=server_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    owner_dir = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    created = owner.create("Installed PRIVATE package", "PRIVATE", structured=True)
    assert created["status"] == "CREATED" and created["visibility"] == "PRIVATE"
    workspace_id = created["workspace_id"]
    assert owner.read(workspace_id)["sequence"] == 1
    owner_identity = peerwork.open_identity(str(owner_dir / "identity.state"))
    assert owner_identity["actor_id"]
    owner_actor = owner_identity["actor_id"]
    vector = json.loads((SOURCE / "conformance/public-package-vectors.json").read_text())
    root_digest = vector["closure"]["root_package_digest"]
    protocol_digest = vector["protocol_digest"]
    material_json = json.dumps({"v": 1, "closure": vector["closure"], "bindings": {}},
                               separators=(",", ":"))
    config = dict(origin=origin, stateDir=str(owner_dir), allowLoopbackHttp=True)
    config_file = STATE / "owner.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(owner_dir),
                                           allow_loopback_http=True)))

    before = counts(origin)["commits"]
    stager = owner.private_package_stager(workspace_id)
    stage = stager.stage(material_json, expected_root_package_digest=root_digest,
                         expected_protocol_digest=protocol_digest)
    assert stage["part_count"] == 1 and stage["protocol_digest"] == protocol_digest
    assert stage["root_package_digest"] == root_digest and stage["source_id"]
    for _ in range(3):
        if stage["status"] == "STAGED":
            break
        stage = stager.continue_stage(stage["stage_id"])
    assert stage["status"] == "STAGED" and stage["applied_parts"] == 1
    assert counts(origin)["commits"] == before + 1

    instance_id = secrets.token_urlsafe(32)
    assert len(instance_id) == 43
    selection = dict(stageId=stage["stage_id"], instanceId=instance_id,
        entrypoint="proposal", grantsJson=json.dumps([dict(actor_id=owner_actor,
        actions=["proposal.propose"], protocol_roles=["AUTHOR"], capabilities=["PROPOSE"])],
        separators=(",", ":")))
    post(origin, "__test/drop-next-post")
    # The native BEGIN completes in a child, but its generated command ID is
    # deliberately withheld from this supervising caller.
    first = node_call(config, workspace_id, "beginWithoutId", selection=selection)
    assert set(first) == {"status", "step_action_id", "protocol_digest", "instance_id"}
    assert first == dict(status="PENDING", step_action_id="secure.structure.begin",
                         protocol_digest=protocol_digest, instance_id=instance_id)
    assert counts(origin)["commits"] == before + 2
    del owner
    reopened = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    saved = reopened.private_package_installer(workspace_id).installs()
    assert len(saved) == 1 and saved[0]["locally_saved"] is True
    assert saved[0]["stage_id"] == stage["stage_id"]
    assert saved[0]["instance_id"] == instance_id
    assert saved[0]["protocol_digest"] == protocol_digest
    begin_id = saved[0]["begin_command_id"]

    post(origin, "__test/drop-next-post")
    end = cli("owner-private-install-continue", config_file, workspace_id, begin_id)
    assert end["status"] == "PENDING" and end["step_action_id"] == "secure.structure.end"
    assert end["begin_command_id"] == begin_id
    assert counts(origin)["commits"] == before + 3
    accepted = node_call(config, workspace_id, "continueInstall", beginId=begin_id)
    assert accepted["status"] == "ACCEPTED" and accepted["step_action_id"] == "secure.structure.end"
    assert accepted["begin_command_id"] == begin_id
    assert accepted["protocol_digest"] == protocol_digest
    assert accepted["instance_id"] == instance_id
    assert counts(origin)["commits"] == before + 3
    active = reopened.read(workspace_id)
    assert active["structure_status"] == "ACTIVE"
    assert any(row.get("kind") == "instances" and row.get("id") == instance_id
        and row.get("value", {}).get("protocol_digest") == protocol_digest
        for row in active["objects"])

    title, body = "Installed encrypted proposal", "Exact PRIVATE content after install"
    proposed = node_call(config, workspace_id, "propose", instanceId=instance_id,
                         title=title, body=body)
    assert proposed["status"] == "PENDING"
    action_id = proposed["command_id"]
    accepted_action = reopened.private_actions(workspace_id).retry_saved(action_id)
    assert accepted_action["status"] == "ACCEPTED"
    assert accepted_action["receipt"]["actor_id"] == owner_actor
    effects = accepted_action["receipt"]["effects"]
    assert len(effects) == 1 and effects[0]["record_id"]
    record_id = effects[0]["record_id"]
    read = reopened.read(workspace_id)
    record = next(row for row in read["objects"] if row.get("id") == record_id)
    assert record["kind"] == "records"
    assert record["value"]["payload"]["title"] == title
    assert record["value"]["payload"]["body"] == body
    assert cli("owner-private-action-retry", config_file, workspace_id, action_id)["status"] == "ACCEPTED"
    assert cli("owner-private-install-continue", config_file, workspace_id, begin_id)["status"] == "ACCEPTED"
    assert counts(origin)["commits"] == before + 4
    assert counts(origin)["head_sequence"] == read["sequence"]

    server.terminate()
    server.wait(timeout=5)
    rows_python = reopened.private_package_installer(workspace_id).installs()
    rows_node = node_call(config, workspace_id, "installs")
    rows_cli = cli("owner-private-install-list", config_file, workspace_id)
    assert rows_python == rows_node == rows_cli
    assert len(rows_python) == 1 and rows_python[0]["begin_command_id"] == begin_id
    print(json.dumps(dict(status="PASS", workspace_id=workspace_id, stage_id=stage["stage_id"],
        begin_command_id=begin_id, protocol_digest=protocol_digest,
        instance_id=instance_id, record_id=record_id, final_sequence=read["sequence"],
        offline_saved_id=True, signed_active=True, installed=True)))
finally:
    if server.poll() is None:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
