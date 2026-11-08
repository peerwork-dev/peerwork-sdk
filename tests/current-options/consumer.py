"""Three current installed optional disclosure/checkpoint recovery and use flows.

The host supplies genuine f828 protected source snapshots. The SDK consumer uses
only explicit source paths and public operations; SQLite counts are test-driver
oracles, not Agent-visible SDK state. Each fresh workspace exercises one public interface end to end on Linux.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess

import peerwork

SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
for relative, key in (
    ("crates/runtime/src/secure_owner_attach.rs", "PEERWORK_TEST_ATTACH_SOURCE_SHA256"),
    ("tests/legacy-owner-install-intent.mjs", "PEERWORK_TEST_LEGACY_HELPER_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_REFERENCE_FIXTURE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[key]
fixture = json.loads(Path(os.environ["PEERWORK_TEST_HOST_FIXTURE_JSON"]).read_text())
origin = fixture["origin"]
assert origin.startswith("http://127.0.0.1:") and STATE.is_dir()
assert STATE.stat().st_mode & 0o077 == 0
sources = fixture["sources"]
modes = ("direct-disclosure-begin-before-post",)
assert {(item["interface"], item["mode"]) for item in sources} == {
    (interface, mode) for interface in (os.environ["PEERWORK_TEST_INTERFACE"],) for mode in modes}
assert len(sources) == 1
request_log = Path(fixture["request_log"])
fixture_request_lines = fixture["fixture_request_lines"]

def observed(workspace):
    # This is a service-side operator oracle, not native storage or a SDK result.
    rows = [json.loads(line) for line in request_log.read_text().splitlines()[fixture_request_lines:]]
    from urllib.parse import urlsplit
    expected_host = urlsplit(origin).netloc
    return [row for row in rows if row["host"] == expected_host
            and row["path"] == f"/api/workspace/v1/secure/workspaces/{workspace}/commits"]

def count(database: Path, workspace: str, command: str | None = None) -> int:
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        if command is None:
            return connection.execute("SELECT count(*) FROM secure_commits WHERE workspace_id=?",
                                      (workspace,)).fetchone()[0]
        return connection.execute("SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?",
                                  (workspace, command)).fetchone()[0]

def node_call(config: dict, operation: str, **values):
    code = r'''
void (async () => {
  const fs = require('node:fs');
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const owner = sdk.openSecureOwnerWorkspaces(JSON.parse(process.env.PEERWORK_TEST_OWNER_CONFIG));
  const value = JSON.parse(fs.readFileSync(0, 'utf8'));
  let result;
  switch (process.env.PEERWORK_TEST_OPERATION) {
    case 'inspect': result = value.completed
      ? await owner.inspectCompletedDirectInstall(value.input, value.commandId, value.optionsJson, value.materialJson)
      : await owner.inspectPendingDirectInstallPacket(value.input, value.commandId, value.optionsJson, value.materialJson); break;
    case 'attach': result = value.completed
      ? await owner.attachCompletedDirectInstall(value.input, value.commandId, value.digest, value.optionsJson, value.materialJson)
      : await owner.attachPendingDirectInstallPacket(value.input, value.commandId, value.digest, value.optionsJson, value.materialJson); break;
    case 'recover': result = await owner.recoverPendingDirectInstallPacket(
      value.attachId, value.commandId); break;
    case 'resume': result = await owner.resumeAttachment(value.attachId); break;
    case 'installs': result = await owner.privatePackageInstaller(value.workspaceId).installs(); break;
    case 'attachments': result = await owner.attachments(); break;
    case 'read': result = await owner.read(value.workspaceId); break;
    case 'action-submit': result = await owner.privateActions(value.workspaceId).submit('set', value.instanceId, {}, {commandId:value.actionCommand}); break;
    case 'action-status': result = await owner.privateActions(value.workspaceId).reconcile(value.actionCommand); break;
    case 'action-retry': result = await owner.privateActions(value.workspaceId).retrySaved(value.actionCommand); break;
    default: throw new Error('invalid test operation');
  }
  console.log(JSON.stringify({ok:true,value:result}));
})().catch(error => console.log(JSON.stringify({ok:false,code:error.code,message:error.message})));
'''
    env = dict(os.environ, PEERWORK_TEST_NODE_PACKAGE=NODE_PACKAGE,
               PEERWORK_TEST_OWNER_CONFIG=json.dumps(config),
               PEERWORK_TEST_OPERATION=operation)
    output = subprocess.run([NODE, "-e", code], env=env, input=json.dumps(values),
                            capture_output=True, text=True, timeout=240)
    assert output.returncode == 0, "Node historical direct packet/completed wrapper failed"
    return json.loads(output.stdout)

def cli(config_file: Path, verb: str, *args):
    output = subprocess.run([CLI, "secure", verb, str(config_file),
                             *(str(arg) for arg in args)],
                            capture_output=True, text=True, timeout=240)
    return dict(ok=output.returncode == 0,
                value=json.loads(output.stdout if output.returncode == 0 else output.stderr))

def source_input(item):
    return dict(workspace_id=item["workspace_id"],
                protected_ts_state_path=item["state_path"],
                protected_ts_intent_db_path=item["intent_db_path"],
                protected_owner_pkcs8_path=item["pem_path"],
                expected_owner_actor_id=item["owner_actor_id"],
                expected_owner_key_id=item["owner_key_id"])

def node_input(value):
    return dict(workspaceId=value["workspace_id"],
                protectedTsStatePath=value["protected_ts_state_path"],
                protectedTsIntentDbPath=value["protected_ts_intent_db_path"],
                protectedOwnerPkcs8Path=value["protected_owner_pkcs8_path"],
                expectedOwnerActorId=value["expected_owner_actor_id"],
                expectedOwnerKeyId=value["expected_owner_key_id"])

def invoke(interface, operation, owner, node_config, config_file, source_file,
           selected, command, digest, options, material, options_file, material_file,
           attach_id=None, workspace=None, completed=False):
    if interface == "python":
        try:
            if operation == "inspect":
                method = owner.inspect_completed_direct_install if completed else owner.inspect_pending_direct_install_packet
                selector = {"selected_instance_id" if completed else "selected_command_id": command}
                return dict(ok=True, value=method(**selected, **selector, options_json=options, material_json=material))
            if operation == "attach":
                method = owner.attach_completed_direct_install if completed else owner.attach_pending_direct_install_packet
                selector = {"selected_instance_id" if completed else "selected_command_id": command}
                return dict(ok=True, value=method(**selected, **selector, expected_ts_state_digest=digest,
                    options_json=options, material_json=material))
            if operation == "recover":
                return dict(ok=True, value=owner.recover_pending_direct_install_packet(
                    attach_id, command))
            if operation == "resume":
                return dict(ok=True, value=owner.resume_attachment(attach_id))
            if operation == "installs":
                return dict(ok=True, value=owner.private_package_installer(workspace).installs())
            if operation == "attachments":
                return dict(ok=True, value=owner.attachments())
            if operation == "read":
                return dict(ok=True, value=owner.read(workspace))
            if operation == "action-submit":
                return dict(ok=True, value=owner.private_actions(workspace).submit('set', current_instance, {}, command_id='r'*43))
            if operation == "action-status":
                return dict(ok=True, value=owner.private_actions(workspace).reconcile('r'*43))
            if operation == "action-retry":
                return dict(ok=True, value=owner.private_actions(workspace).retry_saved('r'*43))
        except (peerwork.OwnerWorkspaceError, peerwork.PrivatePackageStageError) as error:
            return dict(ok=False, code=error.code)
    if interface == "node":
        if operation in ("inspect", "attach"):
            return node_call(node_config, operation, input=node_input(selected), completed=completed,
                commandId=command, digest=digest, optionsJson=options, materialJson=material)
        if operation == "recover":
            return node_call(node_config, operation, attachId=attach_id, commandId=command)
        if operation == "resume":
            return node_call(node_config, operation, attachId=attach_id)
        return node_call(node_config, operation, workspaceId=workspace, instanceId=current_instance, actionCommand="r"*43)
    assert interface == "cli"
    family = "owner-direct-completed" if completed else "owner-direct-packet"
    if operation == "inspect":
        return cli(config_file, family + "-inspect", source_file, command,
                   options_file, material_file)
    if operation == "attach":
        return cli(config_file, family + "-attach", source_file, command,
                   digest, options_file, material_file)
    if operation == "recover":
        return cli(config_file, "owner-direct-packet-recover", attach_id, command)
    if operation == "resume":
        return cli(config_file, "owner-attach-resume", attach_id)
    if operation == "installs":
        return cli(config_file, "owner-private-install-list", workspace)
    if operation == "attachments":
        return cli(config_file, "owner-attachments")
    if operation == "read":
        return cli(config_file, "owner-read", workspace)
    if operation == "action-submit":
        action_file = STATE / ('action-' + interface + '.json')
        action_file.write_text(json.dumps(dict(action_id='set',instance_id=current_instance,body_json='{}',command_id='r'*43)));action_file.chmod(0o600)
        return cli(config_file, 'owner-private-action-submit', workspace, action_file)
    if operation == "action-status":return cli(config_file, 'owner-private-action-status', workspace, 'r'*43)
    if operation == "action-retry":return cli(config_file, 'owner-private-action-retry', workspace, 'r'*43)
    raise AssertionError("unknown operation")

def error_code(response, interface):
    return response["value"]["code"] if interface == "cli" else response["code"]

database = STATE / "kernel/control.sqlite"
for item in sources:
    interface, mode = item["interface"], item["mode"]
    suffix = item["fixture_dir"]
    completed = mode == "direct-completed-end"
    baseline = item["latest_sequence"]
    expected_baseline = 2
    current_instance = item["instance_id"]
    assert baseline == expected_baseline
    workspace = item["workspace_id"]
    command = item["instance_id"] if completed else item["pending_command_id"]
    assert item["pending_count"] == (0 if completed else 1)
    assert count(database, workspace) == baseline
    if not completed:
        assert count(database, workspace, command) == (1 if mode.endswith("applied-loss") else 0)
    options_file, material_file = Path(item["options_path"]), Path(item["material_path"])
    options, material = options_file.read_text(), material_file.read_text()
    assert options and material
    parsed_options=json.loads(options)
    assert parsed_options['expected_checkpoint']==item['expected_checkpoint'] and item['expected_checkpoint']['sequence']==2
    assert parsed_options['disclose']==[dict(schema='item',fields=['title','label'])]
    assert len(parsed_options['grants'])==1 and parsed_options['grants'][0]['actor_id']==item['owner_actor_id'] and parsed_options['grants'][0]['actions']==['set']
    assert item['canonical_options_hash']!=item['intent_hash']
    native = STATE / f"native-{suffix}"
    owner = peerwork.SecureOwnerWorkspaceClient(origin, str(native), allow_loopback_http=True) if interface == "python" else None
    node_config = dict(origin=origin, stateDir=str(native), allowLoopbackHttp=True)
    config_file = STATE / f"config-{suffix}.json"
    config_file.write_text(json.dumps(dict(origin=origin, state_dir=str(native), allow_loopback_http=True)))
    config_file.chmod(0o600)
    source_file = STATE / f"source-{suffix}.json"
    selected = source_input(item)
    source_file.write_text(json.dumps(selected));source_file.chmod(0o600)
    def call(operation, *, selected_command=None, inspected_digest=None,
             selected_options=None, options_path=None, selected_material=None, material_path=None, attachment=None):
        return invoke(interface, operation, owner, node_config, config_file, source_file,
            selected, command if selected_command is None else selected_command,
            inspected_digest, options if selected_options is None else selected_options,
            material if selected_material is None else selected_material,
            options_file if options_path is None else options_path,
            material_file if material_path is None else material_path, attach_id=attachment, workspace=workspace, completed=completed)
    inspected = call("inspect")
    assert inspected["ok"] is True, {"interface":interface,"mode":mode,"phase":"inspect"}
    inventory = inspected["value"]
    assert inventory["instance_id"] == item["instance_id"]
    assert inventory["intent_hash"] == item["intent_hash"]
    assert len(inventory["ts_state_digest"]) == 64
    if completed:
        assert inventory["status"] == "COMPLETED_IN_SIGNED_REPLAY"
        assert inventory["end_sequence"] == baseline
        assert inventory["protocol_digest"] == item["protocol_digest"]
        assert inventory["begin_command_id"] == item["historical_begin_command_id"]
        assert inventory["begin_commit_hash"] == item["historical_begin_commit_hash"]
    else:
        assert inventory["command_id"] == command
        assert inventory["original_commit_hash"] == item["pending_commit_hash"]
        assert inventory["status"] == ("APPLIED_IN_SIGNED_REPLAY" if mode.endswith("applied-loss") else "PENDING_UNRESOLVED")
    assert call("attachments") == dict(ok=True, value=[])
    assert count(database, workspace) == baseline and observed(workspace) == []
    wrong = call("inspect", selected_command="z" * 43)
    assert wrong["ok"] is False and error_code(wrong, interface) == "SOURCE_UNRESOLVED"
    altered = json.loads(options);altered["entrypoint"] = "different_entrypoint"
    altered_json = json.dumps(altered)
    altered_file = STATE / f"altered-options-{suffix}.json"
    altered_file.write_text(altered_json);altered_file.chmod(0o600)
    wrong = call("inspect", selected_options=altered_json, options_path=altered_file)
    assert wrong["ok"] is False and error_code(wrong, interface) == "SOURCE_UNRESOLVED"
    wrong_material_file = STATE / f"wrong-material-{suffix}.json"
    wrong_material_file.write_text("{}");wrong_material_file.chmod(0o600)
    wrong = call("inspect", selected_material="{}", material_path=wrong_material_file)
    assert wrong["ok"] is False and error_code(wrong, interface) == "SOURCE_UNRESOLVED"
    for variant in ('checkpoint','disclosure','grants'):
        changed=json.loads(options)
        if variant=='checkpoint':changed['expected_checkpoint']['sequence']-=1
        elif variant=='disclosure':changed['disclose'][0]['fields']=['secret']
        else:changed['grants'][0]['actor_id']='z'*43
        changed_text=json.dumps(changed);changed_path=STATE/(f'wrong-{variant}-{suffix}.json')
        changed_path.write_text(changed_text);changed_path.chmod(0o600)
        refusal=call('inspect',selected_options=changed_text,options_path=changed_path)
        assert refusal['ok'] is False and error_code(refusal,interface)=='SOURCE_UNRESOLVED',variant
    wrong = call("attach", inspected_digest="0" * 64)
    assert wrong["ok"] is False and error_code(wrong, interface) == "SOURCE_CHANGED"
    assert call("attachments") == dict(ok=True, value=[])
    assert count(database, workspace) == baseline and observed(workspace) == []
    attached = call("attach", inspected_digest=inventory["ts_state_digest"])
    assert attached["ok"] is True, {"interface":interface,"mode":mode,"phase":"attach"}
    progress = attached["value"]
    assert progress["status"] == ("ATTACHED" if completed else "ATTACHED_RESTRICTED")
    assert progress["pending_direct_install_instance_id"] == item["instance_id"]
    assert progress["pending_direct_install_command_id"] == (inventory["begin_command_id"] if completed else command)
    assert progress["pending_direct_install_status"] == ("ACCEPTED" if completed else "PENDING_UNRESOLVED")
    assert count(database, workspace) == baseline and observed(workspace) == []
    attach_id = progress["attach_id"]
    shutil.move(str(STATE / suffix), str(STATE / f"archived-{suffix}"))
    for key in ("state_path", "pem_path", "intent_db_path", "options_path", "material_path"):
        assert not Path(item[key]).exists()
    if interface == "python":
        owner = peerwork.SecureOwnerWorkspaceClient(origin, str(native), allow_loopback_http=True) if interface == "python" else None
    assert call("attachments") == dict(ok=True, value=[progress])
    if completed:
        assert call("resume", attachment=attach_id) == dict(ok=True, value=progress)
        assert count(database, workspace) == baseline and observed(workspace) == []
    else:
        wrong = call("recover", selected_command="z" * 43, attachment=attach_id)
        assert wrong["ok"] is False and error_code(wrong, interface) == "ATTACH_CONFLICT"
        assert count(database, workspace) == baseline and observed(workspace) == []
        for _ in range(128):
            if progress["status"] == "ATTACHED":break
            response = call("recover", attachment=attach_id)
            assert response["ok"] is True, {"interface":interface,"mode":mode,"phase":"recover"}
            progress = response["value"]
            assert progress["status"] in ("ATTACHED_RESTRICTED", "ATTACHED")
        assert progress["status"] == "ATTACHED" and progress["pending_direct_install_status"] == "ACCEPTED"
        assert count(database, workspace, command) == 1
        expected_count = 4
        assert count(database, workspace) == expected_count
        with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
            assert connection.execute("SELECT commit_hash FROM secure_commits WHERE workspace_id=? AND command_id=?",
                (workspace,command)).fetchone()[0] == item["pending_commit_hash"]
        recorded = [row for row in observed(workspace) if row["command_id"] == command]
        if mode.endswith("before-post"):
            assert len(recorded) == 1
            assert {key:recorded[0][key] for key in ("method","path","body_sha256")} == item["expected_native_request"]
        else:
            assert recorded == [], "accepted selected packet was posted again"
        if mode == "direct-end-applied-loss":
            assert observed(workspace) == [], "accepted END recovery unexpectedly posted"
    read = call("read")
    assert read["ok"] is True
    readback = read["value"]
    assert readback["sequence"] == count(database, workspace) and readback["structure_status"] == "ACTIVE"
    assert any(row["kind"] == "instances" and row["id"] == item["instance_id"]
        and row["value"]["protocol_digest"] == item["protocol_digest"]
        and row["value"]["origin_entrypoint"] == item["entrypoint"] for row in readback["objects"])
    assert any(row["kind"] == "protocols" and row["id"] == item["protocol_digest"] for row in readback["objects"])
    installs = call("installs")
    assert installs["ok"] is True
    # Imported rows remain restricted to named attachment recovery and are
    # permanently excluded from ordinary installer discovery, even after END.
    assert installs["value"] == []
    accepted_count = count(database, workspace)
    accepted_requests = observed(workspace)
    repeat = call("resume" if completed else "recover", attachment=attach_id)
    assert repeat == dict(ok=True, value=progress)
    assert count(database, workspace) == accepted_count and observed(workspace) == accepted_requests
    assert call("attachments") == dict(ok=True, value=[progress])
    # Hash-bind the task-local service's exact policy to the already verified read.
    with sqlite3.connect(f'file:{database}?mode=ro',uri=True) as connection:
        policies=connection.execute('SELECT artifact FROM secure_policies WHERE workspace_id=? AND policy_hash=?',(workspace,readback['policy_hash'])).fetchall()
        commit=connection.execute('SELECT artifact FROM secure_commits WHERE workspace_id=? AND sequence=?',(workspace,readback['sequence'])).fetchone()[0]
    assert len(policies)==1 and hashlib.sha256(policies[0][0].encode()).hexdigest()==readback['policy_hash']
    assert hashlib.sha256(commit.encode()).hexdigest()==readback['head']
    policy=json.loads(policies[0][0])['payload']
    protocol=next(p for p in policy['structure']['protocols'] if p['protocol_digest']==item['protocol_digest'])
    for field in ['title','label']:
        assert protocol['schemas']['item']['fields'][field]==dict(protection='server_readable',type='opaque')
    assert protocol['schemas']['item']['fields']['secret']==dict(protection='e2ee',type='string')
    disclosure=[r for r in policy['structure']['disclosure'] if r['protocol_digest']==item['protocol_digest']]
    assert len(disclosure)==1 and disclosure[0]['schema']=='item' and disclosure[0]['fields']==['label','title']
    assert call('action-submit')['ok'] is True
    accepted=call('action-status');assert accepted['ok'] is True
    result=accepted['value'];receipt=result['receipt']
    assert result['status']=='ACCEPTED' and result['command_id']=='r'*43 and result['sequence']==5
    assert receipt['command_id']==result['command_id'] and receipt['sequence']==5 and receipt['commit_hash']==result['commit_hash'] and receipt['actor_id']==item['owner_actor_id'] and receipt['effects']==[]
    final=call('read')['value'];assert final['sequence']==5 and final['head']==result['commit_hash']
    latest=max((r for r in final['objects'] if r['kind']=='instances' and r['id']==item['instance_id']),key=lambda r:r['revision'])
    assert latest['revision']==2 and latest['value']['state']['count']==1
    before_repeat=observed(workspace)
    assert call('action-retry')==accepted and observed(workspace)==before_repeat and count(database,workspace)==5
    print(json.dumps({"interface":interface,"mode":mode,"status":progress["status"],
        "sequence":final["sequence"],"selected_packet_count":0 if completed else 1,
        "native_commit_posts":len(before_repeat),"source_removed":True,"options":["expected_checkpoint","disclose","grants"],"granted_action_readback":True}),flush=True)
print("current installed disclosure/checkpoint/granted use selected-interface PASS")
