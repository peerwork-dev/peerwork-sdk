"""Three independent installed PUBLIC Owner install/action/read paths.

The closure comes from an externally pinned reference vector, not catalog
discovery. This scripted test observes interface behavior; it is not an Agent.
"""

import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import urllib.request

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, variable in (
    ("crates/runtime/src/secure_owner_create.rs", "PEERWORK_TEST_OWNER_SOURCE_SHA256"),
    ("crates/runtime/src/secure_public_install.rs", "PEERWORK_TEST_PUBLIC_INSTALL_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_FIXTURE_SHA256"),
    ("conformance/private-package-options-reference.json", "PEERWORK_TEST_OPTIONS_VECTOR_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[variable]
binding = json.loads((SOURCE / "conformance/private-package-options-reference.json").read_text())["binding"]
assert binding["root_package_digest"] == os.environ["PEERWORK_TEST_BINDING_ROOT_DIGEST"]
assert binding["selected_protocol_digest"] == os.environ["PEERWORK_TEST_BOUND_PROTOCOL_DIGEST"]
assert binding["default_protocol_digest"] == os.environ["PEERWORK_TEST_DEFAULT_PROTOCOL_DIGEST"]
assert binding["selected_protocol_digest"] != binding["default_protocol_digest"]
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=10) as response:
        return json.load(response)["commits"]


NODE_CODE = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const cfg = JSON.parse(process.env.PEERWORK_TEST_CONFIG);
  const input = JSON.parse(process.env.PEERWORK_TEST_INPUT);
  const owner = sdk.openSecureOwnerWorkspaces(cfg);
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'prepare': result = await owner.prepare(input); break;
    case 'operations': result = await owner.operations(); break;
    case 'resume': result = await owner.resume(input.commandId); break;
    case 'identity': result = await sdk.openIdentity(input.path); break;
    case 'read': result = await owner.read(input.workspaceId); break;
    case 'installBegin': result = await owner.publicInstaller(input.workspaceId).begin(input.selection); break;
    case 'installPending': result = await owner.publicInstaller(input.workspaceId).pending(); break;
    case 'installContinue': result = await owner.publicInstaller(input.workspaceId).continueInstall(input.commandId); break;
    case 'actionSubmit': result = await owner.publicActions(input.workspaceId).submit('vote', input.instanceId, {}); break;
    case 'actionPending': result = await owner.publicActions(input.workspaceId).pending(); break;
    case 'actionReconcile': result = await owner.publicActions(input.workspaceId).reconcile(input.commandId); break;
    case 'actionRetry': result = await owner.publicActions(input.workspaceId).retrySaved(input.commandId); break;
    default: throw new Error('unknown test operation');
  }
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error.code || error.message); process.exitCode = 1; });
'''


class Interface:
    def __init__(self, kind, origin):
        self.kind = kind
        self.root = STATE / kind / "protected-owner"
        self.root.parent.mkdir(mode=0o700)
        self.config = dict(origin=origin, state_dir=str(self.root), allow_loopback_http=True)
        self.config_file = STATE / kind / "owner-config.json"
        self.config_file.write_text(json.dumps(self.config))

    def python(self):
        return peerwork.SecureOwnerWorkspaceClient(self.config["origin"], str(self.root),
                                                  allow_loopback_http=True)

    def node(self, operation, input_value):
        config = dict(origin=self.config["origin"], stateDir=str(self.root),
                      allowLoopbackHttp=True)
        env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
                   PEERWORK_TEST_CONFIG=json.dumps(config),
                   PEERWORK_TEST_OPERATION=operation,
                   PEERWORK_TEST_INPUT=json.dumps(input_value))
        result = subprocess.run([NODE, "-e", NODE_CODE], env=env, capture_output=True,
                                text=True, timeout=120)
        assert result.returncode == 0, (operation, result.stderr[-800:])
        return json.loads(result.stdout)

    def cli(self, verb, *args):
        result = subprocess.run([CLI, "secure", verb, str(self.config_file),
                                 *(str(arg) for arg in args)], capture_output=True,
                                text=True, timeout=120)
        assert result.returncode == 0, (verb, result.stderr[-800:])
        return json.loads(result.stdout)

    def file(self, name, value):
        path = self.config_file.parent / name
        path.write_text(json.dumps(value, separators=(",", ":")))
        return path

    def prepare(self):
        name = "Independent " + self.kind + " binding workspace"
        if self.kind == "python":
            return self.python().prepare(name, "PUBLIC", structured=True)
        if self.kind == "node":
            return self.node("prepare", dict(name=name, visibility="PUBLIC", structured=True))
        return self.cli("owner-prepare", self.file("create-input.json",
            dict(name=name, visibility="PUBLIC", structured=True)))

    def operations(self):
        if self.kind == "python":
            return self.python().operations()
        if self.kind == "node":
            return self.node("operations", {})
        return self.cli("owner-operations")

    def resume(self, command_id):
        if self.kind == "python":
            return self.python().resume(command_id)
        if self.kind == "node":
            return self.node("resume", dict(commandId=command_id))
        return self.cli("owner-resume", command_id)

    def actor(self):
        identity_path = self.root / "identity.state"
        if self.kind == "python":
            return peerwork.open_identity(str(identity_path))["actor_id"]
        if self.kind == "node":
            return self.node("identity", dict(path=str(identity_path)))["actor_id"]
        result = subprocess.run([CLI, "identity", "info", str(identity_path)],
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr[-800:]
        return json.loads(result.stdout)["actor_id"]

    def read(self, workspace_id):
        if self.kind == "python":
            return self.python().read(workspace_id)
        if self.kind == "node":
            return self.node("read", dict(workspaceId=workspace_id))
        return self.cli("owner-read", workspace_id)

    def install_begin(self, workspace_id, selection):
        if self.kind == "python":
            return self.python().public_installer(workspace_id).begin(
                selection["closure_json"], expected_package_id=selection["expected_package_id"],
                expected_package_version=selection["expected_package_version"],
                expected_package_digest=selection["expected_package_digest"],
                expected_protocol_digest=selection["expected_protocol_digest"],
                instance_id=selection["instance_id"], entrypoint=selection["entrypoint"],
                grants_json=selection["grants_json"], bindings=selection["bindings"])
        if self.kind == "node":
            return self.node("installBegin", dict(workspaceId=workspace_id, selection=dict(
                closureJson=selection["closure_json"], bindings=selection["bindings"],
                expectedPackageId=selection["expected_package_id"],
                expectedPackageVersion=selection["expected_package_version"],
                expectedPackageDigest=selection["expected_package_digest"],
                expectedProtocolDigest=selection["expected_protocol_digest"],
                instanceId=selection["instance_id"], entrypoint=selection["entrypoint"],
                grantsJson=selection["grants_json"])))
        return self.cli("owner-install-begin", workspace_id,
                        self.file("install-input.json", selection))

    def install_pending(self, workspace_id):
        if self.kind == "python":
            return self.python().public_installer(workspace_id).pending()
        if self.kind == "node":
            return self.node("installPending", dict(workspaceId=workspace_id))
        return self.cli("owner-install-pending", workspace_id)

    def install_continue(self, workspace_id, command_id):
        if self.kind == "python":
            return self.python().public_installer(workspace_id).continue_install(command_id)
        if self.kind == "node":
            return self.node("installContinue", dict(workspaceId=workspace_id, commandId=command_id))
        return self.cli("owner-install-continue", workspace_id, command_id)

    def action_submit(self, workspace_id, instance_id):
        if self.kind == "python":
            return self.python().public_actions(workspace_id).submit("vote", instance_id, {})
        if self.kind == "node":
            return self.node("actionSubmit", dict(workspaceId=workspace_id, instanceId=instance_id))
        return self.cli("owner-action-submit", workspace_id,
                        self.file("action-input.json", dict(action_id="vote",
                            instance_id=instance_id, body_json="{}")))

    def action_pending(self, workspace_id):
        if self.kind == "python":
            return self.python().public_actions(workspace_id).pending()
        if self.kind == "node":
            return self.node("actionPending", dict(workspaceId=workspace_id))
        return self.cli("owner-action-pending", workspace_id)

    def action_reconcile(self, workspace_id, command_id):
        if self.kind == "python":
            return self.python().public_actions(workspace_id).reconcile(command_id)
        if self.kind == "node":
            return self.node("actionReconcile", dict(workspaceId=workspace_id, commandId=command_id))
        return self.cli("owner-action-status", workspace_id, command_id)

    def action_retry(self, workspace_id, command_id):
        if self.kind == "python":
            return self.python().public_actions(workspace_id).retry_saved(command_id)
        if self.kind == "node":
            return self.node("actionRetry", dict(workspaceId=workspace_id, commandId=command_id))
        return self.cli("owner-action-retry", workspace_id, command_id)


server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-kernel-server.mjs")],
    cwd=SOURCE, env=dict(os.environ, PEERWORK_TEST_STATE=str(STATE),
                         PEERWORK_TEST_FIRST_POST_MODE="normal"),
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"service did not start: {server.stderr.read()[-800:]}"
    origin = json.loads(line)["origin"]
    summaries = []
    for kind in ("python", "node", "cli"):
        api = Interface(kind, origin)
        prepared = api.prepare()
        assert prepared["status"] == "PENDING"
        prepared_workspace = prepared["workspace_id"]
        del prepared
        # Drop the returned generated ID. Reopen through this same interface.
        rows = api.operations()
        assert len(rows) == 1 and rows[0]["status"] == "PENDING"
        assert rows[0]["workspace_id"] == prepared_workspace
        workspace_id = rows[0]["workspace_id"]
        created = api.resume(rows[0]["command_id"])
        assert created["status"] == "CREATED" and created["sequence"] == 1
        assert api.operations()[0]["status"] == "CREATED_LOCAL"
        actor_id = api.actor()
        initial = api.read(workspace_id)
        assert initial["sequence"] == 1 and initial["structure_status"] == "ACTIVE"
        instance_id = secrets.token_urlsafe(32)
        selection = dict(closure_json=json.dumps(binding["closure"], separators=(",", ":")),
            bindings=binding["selected_bindings"], expected_package_id="binding-option",
            expected_package_version="1.0.0",
            expected_package_digest=binding["root_package_digest"],
            expected_protocol_digest=binding["selected_protocol_digest"],
            instance_id=instance_id, entrypoint="binding",
            grants_json=json.dumps([dict(actor_id=actor_id, actions=["vote"],
                protocol_roles=["AUTHOR"], capabilities=[])], separators=(",", ":")))
        submitted = api.install_begin(workspace_id, selection)
        assert submitted["status"] == "PENDING"
        assert submitted["protocol_digest"] == binding["selected_protocol_digest"]
        del submitted
        # Recover the BEGIN ID from this interface's protected local listing.
        local = api.install_pending(workspace_id)
        assert len(local) == 1 and local[0]["workspace_id"] == workspace_id
        begin_id = local[0]["begin_command_id"]
        progress = {"status": "PENDING"}
        for _ in range(8):
            if progress["status"] == "ACCEPTED":
                break
            progress = api.install_continue(workspace_id, begin_id)
        assert progress["status"] == "ACCEPTED"
        before_retry = counts(origin)
        assert api.install_continue(workspace_id, begin_id) == progress
        assert counts(origin) == before_retry
        installed = api.read(workspace_id)
        assert any(row["kind"] == "protocols" and row["id"] == binding["selected_protocol_digest"]
                   for row in installed["objects"])
        instance = [row for row in installed["objects"]
                    if row["kind"] == "instances" and row["id"] == instance_id]
        assert len(instance) == 1 and instance[0]["value"]["protocol_digest"] == binding["selected_protocol_digest"]
        action = api.action_submit(workspace_id, instance_id)
        assert action["status"] == "PENDING"
        del action
        local_actions = api.action_pending(workspace_id)
        assert len(local_actions) == 1 and local_actions[0]["action_id"] == "vote"
        command_id = local_actions[0]["command_id"]
        accepted = api.action_reconcile(workspace_id, command_id)
        assert accepted["status"] == "ACCEPTED"
        assert accepted["receipt"]["actor_id"] == actor_id
        # The pinned vote mutates instance state; it declares no content entities.
        assert accepted["receipt"]["effects"] == []
        before_retry = counts(origin)
        assert api.action_retry(workspace_id, command_id) == accepted
        assert counts(origin) == before_retry
        final = api.read(workspace_id)
        latest = max((row for row in final["objects"]
                      if row["kind"] == "instances" and row["id"] == instance_id),
                     key=lambda row: row["revision"])
        assert latest["revision"] == 2
        assert latest["value"]["protocol_digest"] == binding["selected_protocol_digest"]
        assert latest["value"]["state"]["count"] == 1
        summaries.append(dict(interface=kind, workspace_id=workspace_id,
            begin_id=begin_id, action_id=command_id, final_sequence=final["sequence"]))
    assert len({row["workspace_id"] for row in summaries}) == 3
    print(json.dumps(dict(status="PASS", source_mode="pinned_vector_no_catalog",
                          selected_protocol_digest=binding["selected_protocol_digest"],
                          interfaces=summaries)))
finally:
    server.terminate()
    server.wait(timeout=10)
