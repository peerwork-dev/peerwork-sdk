#!/usr/bin/env python3
"""No-model public CLI proof for exact c5e PRIVATE Wiki installation."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import sys
import time

if len(sys.argv) != 3:
    raise SystemExit("usage: preflight_public_wiki_install.py ACCEPTED_C5E_ROOTfs NEW_PREFLIGHT_DIRECTORY")
rootfs_input = Path(sys.argv[1])
assert rootfs_input.name == "rootfs"
artifact_root = rootfs_input.parent.resolve(strict=True)
assert artifact_root.name == "current-sdk-c5e7a3d"
rootfs = rootfs_input.resolve(strict=True)
assert rootfs.name == "rootfs-managed" and rootfs.parent.name == "historical-direct-873a37d"

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()

cli = rootfs / "work/sdk-current-c5e7a3d/target/release/peerwork"
source = rootfs / "work/sdk-current-c5e7a3d"
node = rootfs / "opt/node24/bin/node"
assert sha(cli) == "d41590a8becd0140f1a84fdcffff2eaf75e3b7fd5d237dfb79400d61d4fc605e"
assert sha(artifact_root / "sdk-source-c5e7a3d.tar") == "1366bc1f37e2fcbc068a96ef3f407d9ba2aa7adb8b43f92e132c7fc10741ed5b"
assert sha(artifact_root / "source-manifest-c5e7a3d.sha256") == "3b9de2409d0afe40e915cba8f913bee98f3c0367f6d55cb6df49f47fe3d9badf"
subprocess.run(["sha256sum", "-c", "--status", str(artifact_root / "source-manifest-c5e7a3d.sha256")], cwd=source, check=True)

reference = Path("/root/workdir/message/.worktrees/e2ee-main-integration-20261006").resolve(strict=True)
task = Path(sys.argv[2]).absolute()
assert not task.exists() and task.parent.is_dir() and not task.parent.is_symlink()
task.mkdir(mode=0o700)
selected = task / "selected"; selected.mkdir(mode=0o700)
operator = task / "operator"; operator.mkdir(mode=0o700)
state_dir = task / "native-state"
assert not state_dir.exists()
author = Path(__file__).with_name("author_wiki_material.mjs")
authored = subprocess.run([str(node), str(author), str(reference), str(selected)], cwd=reference,
                          capture_output=True, text=True, timeout=60)
(operator / "author-process.json").write_text(json.dumps({"returncode":authored.returncode,
    "stdout":authored.stdout,"stderr":authored.stderr})+"\n")
(operator / "author-process.json").chmod(0o600)
if authored.returncode: raise RuntimeError("pinned public Wiki author compilation failed")
proof = json.loads(authored.stdout)
assert proof["protocol_digest"] == "33f799e4b168b28032348a26e8c5d320cb2c43550e3effc60f584dc4561717a3"

pem = selected / "owner-private.pem"
subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(pem)],check=True,
               stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
pem.chmod(0o400)
db_dir = task / "service"; db_dir.mkdir(mode=0o700)
server = subprocess.Popen([str(node), str(source / "tests/reference-kernel-server.mjs")], cwd=source,
    env=dict(os.environ,PEERWORK_REFERENCE_ROOT=str(reference),PEERWORK_TEST_STATE=str(db_dir),
             PEERWORK_TEST_FIRST_POST_MODE="normal"),stdout=subprocess.PIPE,
    stderr=(operator / "service.stderr").open("wb"),start_new_session=True)
finished = False
try:
    ready_line = server.stdout.readline()
    if not ready_line: raise RuntimeError("pinned local service failed before readiness")
    origin = json.loads(ready_line)["origin"]
    config = task / "owner-config.json"
    config.write_text(json.dumps({"origin":origin,"state_dir":str(state_dir),"allow_loopback_http":True})+"\n")
    config.chmod(0o400)
    proc_path = state_dir / "identity.state"
    records = []
    command_log = operator / "public-cli-commands.jsonl"
    def cli_call(label,*args, expected=0):
        argv=[str(cli),*args]
        result = subprocess.run(argv,capture_output=True,text=True,timeout=90)
        row={"label":label,"returncode":result.returncode,
             "stdout_sha256":hashlib.sha256(result.stdout.encode()).hexdigest(),
             "stderr_sha256":hashlib.sha256(result.stderr.encode()).hexdigest(),
             "argv":argv,"stderr_code":None}
        try: row["stderr_code"]=json.loads(result.stderr).get("code")
        except (json.JSONDecodeError,AttributeError): pass
        records.append(row)
        with command_log.open("a") as log: log.write(json.dumps(row,separators=(",",":"))+"\n")
        command_log.chmod(0o600)
        if result.returncode != expected:
            raise RuntimeError(f"public CLI preflight failed at {label} (exit {result.returncode}, code {row['stderr_code']})")
        return json.loads(result.stdout) if result.stdout.strip() else None

    assert not state_dir.exists()
    imported=cli_call("identity-import","identity","import-legacy-owner-pem",str(config),str(pem))
    assert state_dir.is_dir() and proc_path.is_file()
    info=cli_call("identity-info","identity","info",str(proc_path))
    assert isinstance(imported,dict) and set(imported)=={"actor_id","key_id"}
    assert all(isinstance(imported.get(field),str) and imported[field]
               for field in ("actor_id","key_id"))
    assert isinstance(info,dict) and isinstance(info.get("actor_id"),str) and info["actor_id"]
    assert isinstance(info.get("key_id"),str) and info["key_id"]
    assert set(info).issubset({"actor_id","key_id"})
    assert info["actor_id"]==imported["actor_id"] and info["key_id"]==imported["key_id"]

    create_input=task/"workspace-create.json"
    create_input.write_text(json.dumps({"name":"Wiki install preflight","visibility":"PRIVATE","structured":True})+"\n")
    create_input.chmod(0o400)
    created=cli_call("owner-create","secure","owner-create",str(config),str(create_input))
    assert created["status"]=="CREATED" and created["visibility"]=="PRIVATE"
    workspace=created["workspace_id"]
    prior=cli_call("owner-read-before-install","secure","owner-read",str(config),workspace)
    # The signed read intentionally omits owner identifiers; bind grants to
    # the actual imported public identity rather than inferring them from it.
    owner_id=info["actor_id"]

    instance=secrets.token_urlsafe(32)
    assert len(instance)==43
    closure=json.loads((selected/"closure.json").read_text())
    install_input={"closure_json":json.dumps(closure,separators=(",",":")),
      "expected_root_package_digest":proof["root_package_digest"],
      "expected_protocol_digest":proof["protocol_digest"],"instance_id":instance,
      "entrypoint":"wiki","grants_json":json.dumps([{"actor_id":owner_id,
        "actions":["wiki.create"],"protocol_roles":["EDITOR"],"capabilities":["EDIT"]}],separators=(",",":"))}
    install_file=task/"direct-install.json"
    install_file.write_text(json.dumps(install_input)+"\n"); install_file.chmod(0o400)
    begin=cli_call("direct-install-begin","secure","owner-private-install-begin-direct",str(config),workspace,str(install_file))
    assert begin["status"] in {"PENDING","ACCEPTED"}
    begin_id=begin.get("begin_command_id") or begin.get("command_id")
    progress=begin
    for _ in range(10):
        if progress.get("status")=="ACCEPTED": break
        assert begin_id
        progress=cli_call("direct-install-continue","secure","owner-private-install-continue",str(config),workspace,begin_id)
    assert progress["status"]=="ACCEPTED"
    installs=cli_call("direct-install-list","secure","owner-private-install-list",str(config),workspace)
    readback=cli_call("owner-read-after-install","secure","owner-read",str(config),workspace)
    objects=readback.get("objects",[])
    selected_rows=[row for row in objects if row.get("kind")=="instances"
      and row.get("id")==instance]
    selected_ids={row.get("id") for row in selected_rows}
    selected_rows_match=bool(selected_rows) and all(
      row.get("value",{}).get("protocol_digest")==proof["protocol_digest"]
      and row.get("value",{}).get("origin_entrypoint")=="wiki" for row in selected_rows)
    workspace_rows=[row for row in objects if row.get("kind")=="workspaces" and row.get("id")==workspace]
    private_owner_match=(len(workspace_rows)==1 and workspace_rows[0].get("value",{}).get("visibility")=="PRIVATE"
      and workspace_rows[0].get("value",{}).get("owner")==owner_id)
    assert len(selected_ids)==1 and selected_rows_match and private_owner_match
    assert readback.get("sequence",0)>=3
    summary={"status":"PASS","cli_sha256":sha(cli),"source_commit":"f828b6c50a0a58d1e718af90f653b214adcc3328",
      "source_digest":proof["source_digest"],"protocol_digest":proof["protocol_digest"],
      "private_workspace_created":True,"identity_imported_to_configured_path":True,
      "identity_info_public_fields_verified":True,"direct_install_accepted":True,
      "new_instance_id_nonempty":bool(instance),"selected_instance_snapshot_count":len(selected_rows),
      "selected_instance_unique_id_count":len(selected_ids),"selected_instance_all_snapshots_match_package_digest":selected_rows_match,
      "signed_private_workspace_owner_matches_imported_identity":private_owner_match,
      "installed_rows_count":len(installs) if isinstance(installs,list) else None,
      "signed_read_sequence":readback.get("sequence"),"signed_read_workspace_id":workspace,
      "native_state_directory_mode":oct(state_dir.stat().st_mode&0o777),
      "identity_state_mode":oct(proc_path.stat().st_mode&0o777),"commands":records,
      "no_wiki_action_submitted":True,"scope":"separate no-model public CLI create/install preflight"}
    summary_path=operator/"summary.json"
    summary_path.write_text(json.dumps(summary,indent=2)+"\n"); summary_path.chmod(0o600)
    finished=True
    print(json.dumps({"status":"PASS","summary_path":str(summary_path),"workspace_id":workspace,
      "protocol_digest":proof["protocol_digest"],"signed_read_sequence":readback.get("sequence"),
      "cli_sha256":sha(cli)},separators=(",",":")),flush=True)
finally:
    server.send_signal(signal.SIGTERM)
    try: server.wait(timeout=10)
    except subprocess.TimeoutExpired: server.kill(); server.wait()
    service_log=operator/"service.stderr"
    if service_log.exists(): service_log.chmod(0o600)
    if finished:
        summary=json.loads((operator/"summary.json").read_text())
        summary["service_exit_code"]=server.returncode
        summary["service_stderr_sha256"]=sha(service_log)
        (operator/"summary.json").write_text(json.dumps(summary,indent=2)+"\n")
        (operator/"summary.json").chmod(0o600)
