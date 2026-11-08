"""Opt-in installed-service preflight for the official proposal→task workflow.

The tracked secure-agent fixture enrolls the distinct adopter through signed
invite/accept/deliver because the installed SDK lacks membership authoring.
Installed APIs then complete proposal and adoption; the test stops at the
missing composed task package install capability.
"""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import urllib.request

import peerwork


SDK_ROOT = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
SOURCE_COMMIT = os.environ["PEERWORK_TEST_SOURCE_COMMIT"]
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SDK_ROOT, text=True).strip() == SOURCE_COMMIT


def counts(origin):
    with urllib.request.urlopen(origin + "__test/secure-counts", timeout=5) as response:
        return json.load(response)


def node_call(config, operation, command_id):
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_CONFIG=json.dumps(config),
               PEERWORK_TEST_OPERATION=operation,
               PEERWORK_TEST_COMMAND_ID=command_id)
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const config = JSON.parse(process.env.PEERWORK_TEST_CONFIG);
  const id = process.env.PEERWORK_TEST_COMMAND_ID;
  const result = process.env.PEERWORK_TEST_OPERATION === 'continue'
    ? await sdk.openSecurePublicPackageInstaller(config).continueInstall(id)
    : await sdk.openSecurePublicActions(config).reconcile(id);
  console.log(JSON.stringify(result));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr[-1200:]
    return json.loads(result.stdout)


def admit_adopter_through_tracked_owner(origin, state, workspace_id, owner_id, owner_key, instance_id):
    """Explicit fixture setup through the tracked signed invitation route.

    The installed SDK has no member enrollment consumer. This setup must not
    be counted as native enrollment coverage.
    """
    env = dict(os.environ, PEERWORK_TEST_ORIGIN=origin.rstrip("/"), PEERWORK_TEST_STATE=str(state),
               PEERWORK_TEST_WORKSPACE=workspace_id, PEERWORK_TEST_INSTANCE=instance_id,
               PEERWORK_TEST_OWNER_ID=owner_id, PEERWORK_TEST_OWNER_KEY=owner_key,
               PEERWORK_TEST_REFERENCE_ROOT=os.environ["PEERWORK_REFERENCE_ROOT"])
    code = r'''
void (async () => {
  const {readFileSync,writeFileSync} = require('node:fs');
  const {join} = require('node:path');
  const {pathToFileURL} = require('node:url');
  const {createPrivateKey,generateKeyPairSync} = require('node:crypto');
  const root = process.env.PEERWORK_TEST_REFERENCE_ROOT;
  const {SecureAgentClient} = await import(pathToFileURL(join(root,'dist-workspace/src/workspace-secure-agent.js')).href);
  const state = process.env.PEERWORK_TEST_STATE;
  const memberKey = generateKeyPairSync('ed25519').privateKey;
  writeFileSync(join(state,'adopter.pem'),memberKey.export({format:'pem',type:'pkcs8'}),{mode:0o600,flag:'wx'});
  const owner = await SecureAgentClient.open({baseUrl:process.env.PEERWORK_TEST_ORIGIN,
    privateKey:createPrivateKey(readFileSync(join(state,'synthetic-public-read-owner.pem'))),
    statePath:join(state,'synthetic-public-read-agent.json'),
    intentDbPath:join(state,'synthetic-public-read-agent-intents.sqlite')});
  const member = await SecureAgentClient.open({baseUrl:process.env.PEERWORK_TEST_ORIGIN,
    privateKey:memberKey,statePath:join(state,'adopter-agent.json'),
    intentDbPath:join(state,'adopter-agent-intents.sqlite')});
  try {
    await member.publishIdentity();
    const fingerprint=await member.identityFingerprint();
    await owner.confirmIdentity(member.identity.actorId,fingerprint.signing_key_sha256);
    const scopes=[{instance_id:process.env.PEERWORK_TEST_INSTANCE,
      actions:['proposal.adopt'],protocol_roles:['ADOPTER'],capabilities:['ADOPT'],expires_at:null}];
    const offer=await owner.inviteActor(process.env.PEERWORK_TEST_WORKSPACE,member.identity.actorId,scopes,'Adopt proposal');
    const decision=await member.decide(offer,{actorId:process.env.PEERWORK_TEST_OWNER_ID,
      key:process.env.PEERWORK_TEST_OWNER_KEY},'ACCEPT');
    await owner.deliver(offer,decision);
    const journal=await owner.journal(process.env.PEERWORK_TEST_WORKSPACE);
    if(journal.checkpoint.sequence!==4) throw Error(`unexpected enrollment sequence ${journal.checkpoint.sequence}`);
    console.log(JSON.stringify({actor_id:member.identity.actorId,key_id:member.identity.keyId,
      authority:member.transport.authority,
      sequence:journal.checkpoint.sequence}));
  } finally { owner.close(); member.close(); }
})().catch(error => { console.error(error); process.exitCode=1; });
'''
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True, text=True, timeout=90)
    assert result.returncode == 0, result.stderr[-1400:]
    return json.loads(result.stdout)


with tempfile.TemporaryDirectory(prefix="peerwork-official-workflow-") as directory:
    state = Path(directory)
    state.chmod(0o700)
    env = dict(os.environ, PEERWORK_TEST_STATE=str(state), PEERWORK_TEST_PUBLIC_READ="1")
    server = subprocess.Popen([NODE, str(SDK_ROOT / "tests/reference-kernel-server.mjs")],
                              cwd=SDK_ROOT, env=env, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    try:
        line = server.stdout.readline()
        assert line, f"reference service did not start: {server.stderr.read()[-500:]}"
        ready = json.loads(line)
        origin, fixture = ready["origin"], ready["public_read"]
        owner_path = state / "owner.state"
        owner = peerwork.import_legacy_identity_pem(
            str(owner_path), str(state / "synthetic-public-read-owner.pem"))
        assert owner == {"actor_id": fixture["actor_id"], "key_id": fixture["signing_key"]}

        profile = state / "profile"
        config = dict(origin=origin, state_dir=str(profile), identity_path=str(owner_path),
                      workspace_id=fixture["workspace_id"], owner_actor_id=owner["actor_id"],
                      owner_key_id=owner["key_id"], authority=fixture["authority"],
                      required_features=[], allow_loopback_http=True,
                      max_replay_artifact_bytes=64 * 1024 * 1024)
        node_config = dict(origin=origin, stateDir=str(profile), identityPath=str(owner_path),
                           workspaceId=fixture["workspace_id"], allowLoopbackHttp=True)
        installer = peerwork.SecurePublicPackageInstaller(
            origin, str(profile), str(owner_path), fixture["workspace_id"],
            owner_actor_id=owner["actor_id"], owner_key_id=owner["key_id"],
            authority=fixture["authority"], allow_loopback_http=True)
        assert installer.read()["sequence"] == 1
        vector = json.loads((SDK_ROOT / "conformance/public-package-vectors.json").read_text())
        assert vector["name"] == "proposal_adoption"
        selection = dict(closure_json=json.dumps(vector["closure"], separators=(",", ":")),
                         expected_package_id="peerwork-proposal-adoption",
                         expected_package_version="1.0.0",
                         expected_package_digest=vector["package_digest"],
                         expected_protocol_digest=vector["protocol_digest"],
                         instance_id="z" * 43, entrypoint="proposalAdoption")
        before = counts(origin)
        adopter_scope = [dict(actor_id="a" * 43,
                              actions=["proposal.adopt"], protocol_roles=["ADOPTER"],
                              capabilities=["ADOPT"], expires_at=None)]
        try:
            installer.begin(**selection, grants_json=json.dumps(adopter_scope))
        except peerwork.PublicInstallError as error:
            assert error.code == "INSTALL_FAILED", error.code
        else:
            raise AssertionError("PUBLIC install unexpectedly granted an actor absent from signed policy")
        after_refusal = counts(origin)
        assert after_refusal["commits"] == before["commits"]
        assert after_refusal["head_sequence"] == before["head_sequence"]
        assert installer.pending() == []

        author_scope = [dict(actor_id=owner["actor_id"],
                             actions=["proposal.propose"], protocol_roles=["AUTHOR"],
                             capabilities=["PROPOSE"], expires_at=None)]
        begin = installer.begin(**selection, grants_json=json.dumps(author_scope))
        assert begin["status"] == "PENDING"
        step = node_call(node_config, "continue", begin["command_id"])
        for _ in range(5):
            if step["status"] == "ACCEPTED":
                break
            step = node_call(node_config, "continue", begin["command_id"])
        assert step["status"] == "ACCEPTED"
        latest = installer.read()
        assert latest["sequence"] == 3 and latest["structure_status"] == "ACTIVE"

        admitted = admit_adopter_through_tracked_owner(origin, state, fixture["workspace_id"],
                                                        owner["actor_id"], owner["key_id"],
                                                        selection["instance_id"])
        adopter_path = state / "adopter.state"
        adopter = peerwork.import_legacy_identity_pem(str(adopter_path), str(state / "adopter.pem"))
        assert adopter == {"actor_id": admitted["actor_id"], "key_id": admitted["key_id"]}
        assert adopter["actor_id"] != owner["actor_id"]

        actions = peerwork.SecurePublicActionClient(
            origin, str(profile), str(owner_path), fixture["workspace_id"],
            owner_actor_id=owner["actor_id"], owner_key_id=owner["key_id"],
            authority=fixture["authority"], allow_loopback_http=True)
        proposal_id = "p" * 43
        proposed = actions.submit("proposal.propose", selection["instance_id"],
                                  {"title": "Turn decision into task",
                                   "body": "Adopted proposal becomes a traceable task."},
                                  command_id=proposal_id)
        assert proposed["status"] == "PENDING"
        accepted = node_call(node_config, "reconcile", proposal_id)
        assert accepted["status"] == "ACCEPTED" and accepted["sequence"] == 5
        receipt = accepted["receipt"]
        assert receipt["command_id"] == proposal_id and len(receipt["effects"]) == 1
        candidate_id = receipt["effects"][0]["record_id"]
        latest = actions.read()
        assert latest["sequence"] == 5
        candidate = next(obj for obj in latest["objects"] if obj.get("id") == candidate_id)
        assert candidate["kind"] == "records" and candidate["value"]["schema_ref"] == "proposal.candidate"
        assert candidate["value"]["payload"]["author"] == owner["actor_id"]

        config_file = state / "action-config.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")
        retry = subprocess.run([CLI, "secure", "action-retry", str(config_file), proposal_id],
                               capture_output=True, text=True, timeout=90)
        assert retry.returncode == 0, retry.stderr[-1200:]
        assert json.loads(retry.stdout)["status"] == "ACCEPTED"
        assert counts(origin)["head_sequence"] == 5

        member_profile = state / "adopter-profile"
        member_actions = peerwork.SecurePublicActionClient(
            origin, str(member_profile), str(adopter_path), fixture["workspace_id"],
            owner_actor_id=owner["actor_id"], owner_key_id=owner["key_id"],
            authority=admitted["authority"], allow_loopback_http=True)
        assert member_actions.read()["sequence"] == 5
        exact_candidate = {"record_id": candidate_id, "revision": 1}
        adopt_id = "a" * 43
        adopted = member_actions.submit("proposal.adopt", selection["instance_id"],
                                        {"candidate_ref": exact_candidate},
                                        exact_input_refs=[exact_candidate], command_id=adopt_id)
        assert adopted["status"] == "PENDING"
        member_node_config = dict(origin=origin, stateDir=str(member_profile),
                                  identityPath=str(adopter_path), workspaceId=fixture["workspace_id"],
                                  allowLoopbackHttp=True)
        adopted_result = node_call(member_node_config, "reconcile", adopt_id)
        assert adopted_result["status"] == "ACCEPTED" and adopted_result["sequence"] == 6
        assert counts(origin)["head_sequence"] == 6
        adopted_read = member_actions.read()
        assert adopted_read["sequence"] == 6
        adoption_operation = next(
            item for item in adopted_read["operations"]
            if item.get("kind") == "ACTION"
            and item.get("input", {}).get("action_id") == "proposal.adopt")
        assert adoption_operation["input"]["body"]["candidate_ref"] == exact_candidate
        assert adoption_operation["input"]["exact_input_refs"] == [exact_candidate]
        member_config = dict(config, state_dir=str(member_profile), identity_path=str(adopter_path),
                             authority=admitted["authority"])
        member_config_file = state / "adopter-action-config.json"
        member_config_file.write_text(json.dumps(member_config), encoding="utf-8")
        adopter_retry = subprocess.run([CLI, "secure", "action-retry", str(member_config_file), adopt_id],
                                       capture_output=True, text=True, timeout=90)
        assert adopter_retry.returncode == 0, adopter_retry.stderr[-1200:]
        assert json.loads(adopter_retry.stdout)["status"] == "ACCEPTED"
        assert counts(origin)["head_sequence"] == 6
        print(json.dumps({"source_commit": SOURCE_COMMIT,
                          "reference_commit": "f828b6c50a0a58d1e718af90f653b214adcc3328",
                          "adopter_grant_refused_before_post": True,
                          "installed_interfaces": ["Python", "Node", "CLI"],
                          "proposal_sequence": 5, "adoption_sequence": 6,
                          "adopter_enrollment": "tracked TypeScript signed invite fixture",
                          "candidate_id": candidate_id,
                          "full_workflow": "BLOCKED_COMPOSED_TASK_INSTALL_API"}))
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=5)
