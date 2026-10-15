#!/usr/bin/env python3
"""Create one fresh local Owner/wiki task fixture; never launch an actor."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: prepare_private_wiki_task.py ACCEPTED_C5E_ROOTFS NEW_TASK_DIRECTORY")
rootfs_lexical = Path(sys.argv[1])
assert rootfs_lexical.name == "rootfs"
artifact_root = rootfs_lexical.parent.resolve(strict=True)
assert artifact_root.name == "current-sdk-c5e7a3d"
rootfs = rootfs_lexical.resolve(strict=True)
assert rootfs.name == "rootfs-managed" and rootfs.parent.name == "historical-direct-873a37d"
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
assert sha(artifact_root / "sdk-source-c5e7a3d.tar") == "1366bc1f37e2fcbc068a96ef3f407d9ba2aa7adb8b43f92e132c7fc10741ed5b"
assert sha(artifact_root / "source-manifest-c5e7a3d.sha256") == "3b9de2409d0afe40e915cba8f913bee98f3c0367f6d55cb6df49f47fe3d9badf"
assert sha(artifact_root / "artifact-manifest.sha256") == "271e94cf10c812b09bad974358c51b8bbb157afbb7d99fb02c3b90c44e36dd92"
cli = rootfs / "work/sdk-current-c5e7a3d/target/release/peerwork"
assert sha(cli) == "d41590a8becd0140f1a84fdcffff2eaf75e3b7fd5d237dfb79400d61d4fc605e"
source = rootfs / "work/sdk-current-c5e7a3d"
subprocess.run(["sha256sum", "-c", "--status", str(artifact_root / "source-manifest-c5e7a3d.sha256")], cwd=source, check=True)
for rel, expected in {
    "crates/runtime/src/secure_owner_create.rs":"5a886ca74e0e61c432a0298bf6a37c449062c5fe0a5827eb149939bf31bd9f32",
    "crates/runtime/src/secure_state.rs":"e9c08b0d53d8c5d74f3aa11d0e5a9bc4ef7eb6618424837609fa557cad7a0cb2",
    "crates/cli/src/main.rs":"7f49ba758243a59c588761c037607c2f592f5f22d4ec022c4ee8e969b533133d",
}.items(): assert sha(source / rel) == expected
assert len((artifact_root / "artifact-manifest.sha256").read_text().splitlines()) == 14

reference = Path("/root/workdir/message/.worktrees/e2ee-main-integration-20261006").resolve(strict=True)
assert subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip() == "f828b6c50a0a58d1e718af90f653b214adcc3328"
subprocess.run(["git", "-C", str(reference), "diff", "--quiet", "HEAD", "--", "protocols/wiki", "tests/reference-kernel-server.mjs"], check=True)
state = Path(sys.argv[2]).absolute()
assert not state.exists() and state.parent.is_dir() and not state.parent.is_symlink()
state.mkdir(mode=0o700)
actor = state / "actor"; actor.mkdir(mode=0o700)
observer = state / "observer"; observer.mkdir(mode=0o700)
operator = state / "operator"; operator.mkdir(mode=0o700)
selected = actor / "selected-source"; selected.mkdir(mode=0o700)

for rel in ("docs/agent-entry.md",):
    assert sha(source / rel) == "923f0182848171008da8b6e905df102534c48267402a1b8c5c9527ff743df07b"
assert sha(source / "README.md") == "53af28ae253db4219085066fceeb44cb88b2d1b92351747ba3706116b016a5a8"
shutil.copyfile(cli, actor / "peerwork"); (actor / "peerwork").chmod(0o500)
shutil.copyfile(source / "docs/agent-entry.md", actor / "AGENT_ENTRY.md"); (actor / "AGENT_ENTRY.md").chmod(0o400)
shutil.copyfile(source / "README.md", actor / "CLIENT_README.md"); (actor / "CLIENT_README.md").chmod(0o400)
for rel in ("protocols/wiki/package.json", "protocols/wiki/protocol.source.json", "protocols/wiki/release.lock.json", "protocols/wiki/README.md", "protocols/wiki/LICENSE", "protocols/wiki/fixtures/authorized-interaction.json", "protocols/wiki/fixtures/unauthenticated-rejected.json"):
    src = reference / rel
    dst = selected / rel.removeprefix("protocols/wiki/")
    dst.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(src, dst); dst.chmod(0o400)

node = rootfs / "opt/node24/bin/node"
author = Path(__file__).with_name("author_wiki_material.mjs")
author_result = subprocess.run([str(node), str(author), str(reference), str(selected)], cwd=reference, capture_output=True, text=True, timeout=60)
author_log = operator / "author-process.json"
author_log.write_text(json.dumps({"returncode":author_result.returncode,
    "stdout":author_result.stdout, "stderr":author_result.stderr}) + "\n")
author_log.chmod(0o600)
if author_result.returncode != 0: raise RuntimeError("pinned public author compilation failed; protected operator author-process.json retained")
proof = json.loads(author_result.stdout)
assert proof["source_commit"] == "f828b6c50a0a58d1e718af90f653b214adcc3328"
assert proof["protocol_digest"] == "33f799e4b168b28032348a26e8c5d320cb2c43550e3effc60f584dc4561717a3"
assert proof["source_digest"] == "05300473589495f96080b96c78962acc0c0ecc8bf1ae82d84f214042a6d30ca2"
(selected / "author-proof.json").chmod(0o400)
(selected / "closure.json").chmod(0o400)
(selected / "material.json").chmod(0o400)

key = selected / "owner-private.pem"
subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(key)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
key.chmod(0o400)
config = actor / "owner-config.json"
config.write_text(json.dumps({"origin":"PENDING_LOCAL_ORIGIN", "state_dir":str(actor / "native-state"), "allow_loopback_http":True}) + "\n")
config.chmod(0o400)
assert not (actor / "native-state").exists()
(actor / "workspace-request.json").write_text(json.dumps({"name":"Field Lab", "visibility":"PRIVATE", "structured":True}) + "\n")
(actor / "workspace-request.json").chmod(0o400)
environment = {
    "entry":"AGENT_ENTRY.md", "client_readme":"CLIENT_README.md", "peerwork":"peerwork",
    "owner_config":"owner-config.json", "selected_owner_pem":"selected-source/owner-private.pem",
    "selected_protocol_source":"selected-source", "selected_package_material":"selected-source/material.json",
    "direct_install_closure":"selected-source/closure.json", "workspace_request":"workspace-request.json",
    "native_state_directory":"native-state", "protocol_entrypoint":"wiki",
    "expected_protocol_digest":proof["protocol_digest"], "service_origin":"PENDING_LOCAL_ORIGIN",
}
(actor / "ENVIRONMENT.json").write_text(json.dumps(environment, indent=2) + "\n")
(actor / "ENVIRONMENT.json").chmod(0o400)

# Patch only the frozen local proxy response boundary. It recognizes the exact
# action ID after the real service returns 2xx; observation contains identifiers
# and counters only, never the request body, title/body, PEM, or keys.
base_server = source / "tests/reference-kernel-server.mjs"
assert sha(base_server) == "50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0"
server_text = base_server.read_text()
needle = "    const original = await fetch(realOrigin + request.url, {\n"
insert = """    const forwardedBody = Buffer.concat(chunks);
    const original = await fetch(realOrigin + request.url, {
"""
assert server_text.count(needle) == 1
server_text = server_text.replace(needle, insert, 1)
server_text = server_text.replace("body: request.method === 'GET' ? undefined : Buffer.concat(chunks),", "body: request.method === 'GET' ? undefined : forwardedBody,", 1)
needle = "    let bytes = Buffer.from(await original.arrayBuffer());\n"
insert = """    let selectedWikiDrop = null;
    if (request.method === 'POST' && /^\\/api\\/workspace\\/v1\\/secure\\/workspaces\\/[^/]+\\/commits$/.test(request.url)
        && original.status >= 200 && original.status < 300) {
      let actionId = null, commandId = null, workspaceId = null;
      try {
        const wire = JSON.parse(forwardedBody.toString('utf8'));
        actionId = wire.commit?.payload?.action_id ?? null;
        commandId = wire.commit?.payload?.command_id ?? wire.commit?.command_id ?? null;
        workspaceId = wire.commit?.payload?.workspace_id ?? null;
      } catch {}
      if (actionId === 'wiki.create' && !wikiResponseDropObserved) {
        wikiResponseDropObserved = true;
        selectedWikiDrop = {dropped_after_origin_success:true, status:original.status,
          action_id:actionId, command_id:commandId, workspace_id:workspaceId,
          route_class:'secure-commit', observed_at:new Date().toISOString()};
        writeFileSync(process.env.PEERWORK_TEST_WIKI_DROP_OBSERVATION, JSON.stringify(selectedWikiDrop) + '\\n', {mode:0o600, flag:'wx'});
        response.destroy();
        return;
      }
    }
    let bytes = Buffer.from(await original.arrayBuffer());
"""
assert server_text.count(needle) == 1
server_text = server_text.replace(needle, insert, 1)
marker = "let dropFirstPost = true;\n"
assert server_text.count(marker) == 1
server_text = server_text.replace(marker, "let wikiResponseDropObserved = false;\n" + marker, 1)
overlay = operator / "reference-kernel-server.mjs"
overlay.write_text(server_text); overlay.chmod(0o400)
service_stderr = (observer / "service.stderr").open("wb")
env = dict(os.environ, PEERWORK_REFERENCE_ROOT=str(reference), PEERWORK_TEST_STATE=str(operator),
           PEERWORK_TEST_FIRST_POST_MODE="normal", PEERWORK_TEST_WIKI_DROP_OBSERVATION=str(operator / "wiki-drop.json"))
server = subprocess.Popen([str(node), str(overlay)], cwd=source, env=env, stdout=subprocess.PIPE, stderr=service_stderr)
try:
    ready = server.stdout.readline()
    if not ready: raise RuntimeError("reference service failed to become ready")
    origin = json.loads(ready)["origin"]
    config.write_text(json.dumps({"origin":origin, "state_dir":str(actor / "native-state"), "allow_loopback_http":True}) + "\n")
    config.chmod(0o400)
    environment["service_origin"] = origin
    (actor / "ENVIRONMENT.json").write_text(json.dumps(environment, indent=2) + "\n")
    (actor / "ENVIRONMENT.json").chmod(0o400)
    fixture = {"state":"READY", "source_commit":"f828b6c50a0a58d1e718af90f653b214adcc3328",
      "artifact_root":str(artifact_root), "cli_sha256":sha(cli), "protocol_root_digest":proof["root_package_digest"],
      "protocol_source_digest":proof["source_digest"], "protocol_digest":proof["protocol_digest"],
      "control_database":str(operator / "control.sqlite"),
      "workspace_created_by_setup":False, "identity_created_by_setup":False,
      "state_leaf_absent":not (actor / "native-state").exists(), "task_dir_mode":oct(state.stat().st_mode & 0o777),
      "actor_dir_mode":oct(actor.stat().st_mode & 0o777), "observer_dir_mode":oct(observer.stat().st_mode & 0o777),
      "operator_dir_mode":oct(operator.stat().st_mode & 0o777), "origin":origin}
    (observer / "fixture.json").write_text(json.dumps(fixture, indent=2) + "\n")
    (observer / "fixture.json").chmod(0o600)
    print(json.dumps(fixture), flush=True)
    signal.pause()
finally:
    if server.poll() is None:
        server.send_signal(signal.SIGTERM)
        try: server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill(); server.wait()
    service_stderr.close()
