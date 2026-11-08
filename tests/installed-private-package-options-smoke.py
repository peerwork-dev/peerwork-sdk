"""Scripted installed PRIVATE package-option selection across public facades.

The read-only task-local service policy oracle is hash-bound to verified native
read, and is not a public policy getter or an independent signature verifier.
This mixed-interface test does not establish natural Agent workflow compliance.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, variable in (
    ("crates/core/src/public_direct_install.rs", "PEERWORK_TEST_DIRECT_COMPILER_SHA256"),
    ("crates/core/src/prepared_private_install.rs", "PEERWORK_TEST_PRIVATE_PRODUCER_SHA256"),
    ("crates/runtime/src/secure_private_install.rs", "PEERWORK_TEST_RUNTIME_INSTALL_SHA256"),
    ("crates/runtime/src/secure_public_install.rs", "PEERWORK_TEST_PUBLIC_INSTALL_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_FIXTURE_SHA256"),
    ("conformance/private-package-options-reference.json", "PEERWORK_TEST_OPTIONS_VECTOR_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
vector = json.loads((SOURCE / "conformance/private-package-options-reference.json").read_text())
readable = vector["readable"]
binding = vector["binding"]
assert readable["root_package_digest"] == os.environ["PEERWORK_TEST_READABLE_ROOT_DIGEST"]
assert readable["protocol_digest"] == os.environ["PEERWORK_TEST_READABLE_PROTOCOL_DIGEST"]
assert binding["root_package_digest"] == os.environ["PEERWORK_TEST_BINDING_ROOT_DIGEST"]
assert binding["default_protocol_digest"] == os.environ["PEERWORK_TEST_DEFAULT_PROTOCOL_DIGEST"]
assert binding["selected_protocol_digest"] == os.environ["PEERWORK_TEST_BOUND_PROTOCOL_DIGEST"]
assert binding["default_protocol_digest"] != binding["selected_protocol_digest"]
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)["commits"]


def policy_oracle(workspace_id, verified):
    with sqlite3.connect("file:" + str(STATE / "control.sqlite") + "?mode=ro",
                         uri=True, timeout=10) as connection:
        policies = connection.execute(
            "SELECT policy_hash, artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?",
            (workspace_id, verified["policy_hash"])).fetchall()
        commits = connection.execute(
            "SELECT commit_hash, policy_hash, artifact FROM secure_commits WHERE workspace_id=? AND sequence=?",
            (workspace_id, verified["sequence"])).fetchall()
    assert len(policies) == len(commits) == 1
    commit_hash, commit_policy_hash, commit_wire = commits[0]
    assert commit_hash == verified["head"] and commit_policy_hash == verified["policy_hash"]
    assert hashlib.sha256(commit_wire.encode()).hexdigest() == commit_hash
    commit = json.loads(commit_wire)
    assert commit["signature"] and commit["payload"]["sequence"] == verified["sequence"]
    policy_hash, policy_wire = policies[0]
    assert policy_hash == verified["policy_hash"]
    assert hashlib.sha256(policy_wire.encode()).hexdigest() == policy_hash
    policy = json.loads(policy_wire)
    assert policy["signature"]
    return policy["payload"]


def node_call(config, workspace_id, selection):
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_CONFIG));
  const selected = JSON.parse(process.env.PEERWORK_TEST_SELECTION);
  const result = await owner.privatePackageInstaller(process.env.PEERWORK_TEST_WORKSPACE).beginDirect(selected);
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error.code || error.message); process.exitCode = 1; });
'''
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_CONFIG=json.dumps(config),
               PEERWORK_TEST_WORKSPACE=workspace_id,
               PEERWORK_TEST_SELECTION=json.dumps(selection))
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True,
                            text=True, timeout=120)
    assert result.returncode == 0, result.stderr[-800:]
    return json.loads(result.stdout)


def cli(config_file, verb, workspace_id, argument):
    result = subprocess.run([CLI, "secure", verb, str(config_file), workspace_id, str(argument)],
                            capture_output=True, text=True, timeout=120)
    assert result.returncode == 0, (verb, result.stderr[-800:])
    return json.loads(result.stdout)


def accepted_install(installer, progress):
    begin_id = progress["begin_command_id"]
    for _ in range(8):
        if progress["status"] == "ACCEPTED":
            break
        progress = installer.continue_install(begin_id)
    assert progress["status"] == "ACCEPTED"
    return begin_id, progress


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    owner_dir = STATE / "native-owner"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(owner_dir), allow_loopback_http=True)
    config = dict(origin=origin, stateDir=str(owner_dir), allowLoopbackHttp=True)
    config_file = STATE / "owner-config.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(owner_dir),
                                           allow_loopback_http=True)))

    def workspace(label):
        created = owner.create("Installed package options " + label, "PRIVATE", structured=True)
        assert created["status"] == "CREATED"
        workspace_id = created["workspace_id"]
        before = policy_oracle(workspace_id, owner.read(workspace_id))
        assert before["v"] == 3 and before["structure_mode"] == "STRUCTURED"
        assert before["protocol_format_ceiling"] == 1
        raised = owner.submit_format_transition(workspace_id, "RAISE_PRIVATE_CEILING_TWO")
        raised = owner.resume_format_transition(workspace_id, raised["command_id"])
        assert raised["status"] == "ACCEPTED"
        policy = policy_oracle(workspace_id, owner.read(workspace_id))
        assert policy["protocol_format_ceiling"] == 2
        assert not any(p["protocol_digest"] == readable["protocol_digest"]
                       for p in policy["structure"]["protocols"])
        return workspace_id, policy["owner_id"]

    def stage(workspace_id, via_cli):
        material = json.dumps(readable["material"], separators=(",", ":"))
        if via_cli:
            stage_file = STATE / ("stage-" + workspace_id + ".json")
            stage_file.write_text(json.dumps(dict(material_json=material,
                expected_root_package_digest=readable["root_package_digest"],
                expected_protocol_digest=readable["protocol_digest"])))
            progress = cli(config_file, "owner-private-stage-submit", workspace_id, stage_file)
        else:
            progress = owner.private_package_stager(workspace_id).stage(material,
                expected_root_package_digest=readable["root_package_digest"],
                expected_protocol_digest=readable["protocol_digest"])
        stage_id = progress["stage_id"]
        for _ in range(8):
            if progress["status"] == "STAGED":
                break
            progress = owner.private_package_stager(workspace_id).continue_stage(stage_id)
        assert progress["status"] == "STAGED"
        policy = policy_oracle(workspace_id, owner.read(workspace_id))
        assert not any(p["protocol_digest"] == readable["protocol_digest"]
                       for p in policy["structure"]["protocols"])
        return stage_id

    def assert_readable(workspace_id, selected):
        policy = policy_oracle(workspace_id, owner.read(workspace_id))
        protocol = next(p for p in policy["structure"]["protocols"]
                        if p["protocol_digest"] == readable["protocol_digest"])
        field = protocol["schemas"]["item"]["fields"]["label"]
        assert field["protection"] == ("server_readable" if selected else "e2ee")
        assert field["type"] == ("opaque" if selected else "string")
        selected_rows = [(row["schema"], row["fields"])
                         for row in policy["structure"]["disclosure"]
                         if row["protocol_digest"] == readable["protocol_digest"]]
        assert selected_rows == [("item", ["label"] if selected else [])]

    # Python omitted STAGED selection keeps the source's E2EE/string default.
    default_workspace, default_actor = workspace("default staged")
    default_stage = stage(default_workspace, False)
    default_installer = owner.private_package_installer(default_workspace)
    default_begin = default_installer.begin(default_stage, secrets.token_urlsafe(32), "readable",
        grants_json=json.dumps([dict(actor_id=default_actor, actions=["set"],
                                    protocol_roles=[], capabilities=[])]))
    default_id, default_progress = accepted_install(default_installer, default_begin)
    assert_readable(default_workspace, False)
    before_retry = counts(origin)
    assert default_installer.continue_install(default_id) == default_progress
    assert counts(origin) == before_retry

    # CLI selects the same field for a different fresh protocol/workspace.
    selected_workspace, selected_actor = workspace("explicit staged")
    selected_stage = stage(selected_workspace, True)
    selected_installer = owner.private_package_installer(selected_workspace)
    begin_file = STATE / "explicit-staged-begin.json"
    begin_file.write_text(json.dumps(dict(stage_id=selected_stage,
        instance_id=secrets.token_urlsafe(32), entrypoint="readable",
        grants_json=json.dumps([dict(actor_id=selected_actor, actions=["set"],
                                     protocol_roles=[], capabilities=[])]),
        disclose=[dict(schema="item", fields=["label"])])))
    selected_begin = cli(config_file, "owner-private-install-begin", selected_workspace, begin_file)
    selected_id, selected_progress = accepted_install(selected_installer, selected_begin)
    assert_readable(selected_workspace, True)
    before_retry = counts(origin)
    assert selected_installer.continue_install(selected_id) == selected_progress
    assert counts(origin) == before_retry

    # Node accepts a natural binding object; the selected digest is source-pinned.
    bound_workspace, bound_actor = workspace("selected binding")
    bound_installer = owner.private_package_installer(bound_workspace)
    bound = node_call(config, bound_workspace, dict(
        closureJson=json.dumps(binding["closure"], separators=(",", ":")),
        bindings=binding["selected_bindings"],
        expectedRootPackageDigest=binding["root_package_digest"],
        expectedProtocolDigest=binding["selected_protocol_digest"],
        instanceId=secrets.token_urlsafe(32), entrypoint="binding",
        grantsJson=json.dumps([dict(actor_id=bound_actor, actions=["vote"],
                                   protocol_roles=["AUTHOR"], capabilities=[])])))
    bound_id, bound_progress = accepted_install(bound_installer, bound)
    read = owner.read(bound_workspace)
    assert any(row["kind"] == "protocols" and row["id"] == binding["selected_protocol_digest"]
               for row in read["objects"])
    before_retry = counts(origin)
    assert bound_installer.continue_install(bound_id) == bound_progress
    assert counts(origin) == before_retry
    print(json.dumps(dict(default_workspace=default_workspace,
                          selected_workspace=selected_workspace,
                          bound_workspace=bound_workspace,
                          default_begin_id=default_id, selected_begin_id=selected_id,
                          bound_begin_id=bound_id,
                          selected_protocol_digest=binding["selected_protocol_digest"])))
finally:
    server.terminate()
    server.wait(timeout=10)
