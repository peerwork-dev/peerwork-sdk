#!/usr/bin/env python3
"""Run pinned f828 orphan fixture on host and installed consumers in glibc 2.28."""

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys


rootfs = Path(sys.argv[1]).resolve()
source = rootfs / "work/sdk-multipart-orphan"
state = source / "dist/multipart-orphan-state-split"
guest_state = Path("/work/sdk-multipart-orphan/dist/multipart-orphan-state-split")
reference = Path("/root/workdir/message/.worktrees/e2ee-main-integration-20261006")
node = rootfs / "opt/node24/bin/node"
expected = {
    "crates/runtime/src/secure_owner_attach.rs": "47d341987c34f21a533ecee8d255d8dd70bc3ffdc3388f72fd41bcdcf3c5f451",
    "tests/legacy-owner-source.mjs": "4da377dc9bb8831a38d48eb6c0ffb8e9a6263b99e226d2d41b7b57344961232a",
    "tests/reference-kernel-server.mjs": "50168d56f654e51d5d3696815e8cae7590e0a002721ca076ec636bf47d2769b0",
}
for relative, digest in expected.items():
    assert hashlib.sha256((source / relative).read_bytes()).hexdigest() == digest
assert subprocess.check_output(["git", "-C", str(reference), "rev-parse", "HEAD"], text=True).strip() == "f828b6c50a0a58d1e718af90f653b214adcc3328"
assert subprocess.run(["git", "-C", str(reference), "diff", "--quiet", "HEAD", "--", "src", "protocols", "package.json", "package-lock.json", "tsconfig.workspace.json"], check=False).returncode == 0
state.mkdir(mode=0o700, parents=True, exist_ok=False)
snapshot = state / "reference-agent"
snapshot.mkdir(mode=0o700)
archive = state / "reference-agent.tar"
subprocess.run(["git", "-C", str(reference), "archive", "--format=tar",
                "--output", str(archive), "f828b6c50a0a58d1e718af90f653b214adcc3328"], check=True)
subprocess.run(["tar", "-xf", str(archive), "-C", str(snapshot)], check=True)
(snapshot / "node_modules").symlink_to(reference / "node_modules", target_is_directory=True)
lock = json.loads((snapshot / "package-lock.json").read_text())
compiler_package = reference / "node_modules/typescript/package.json"
installed_compiler = json.loads(compiler_package.read_text())
assert lock["packages"]["node_modules/typescript"]["version"] == installed_compiler["version"] == "7.0.2"
compiler_body = reference / "node_modules/typescript/lib/tsc.js"
assert hashlib.sha256(compiler_body.read_bytes()).hexdigest() == "cbdfbf11c26ed00dfc073155e316a42d6d6d8a387be61006b82fa9aa93ac572e"
assert hashlib.sha256((reference / "node_modules/typescript/bin/tsc").read_bytes()).hexdigest() == "2219f428a7e55aaf1f7ad85b9b0f0cf5078aeb76ccc9a7c6036c92d48f492ffd"
assert hashlib.sha256((reference / "node_modules/typescript/lib/getExePath.js").read_bytes()).hexdigest() == "96c10fd3a18e165d7323de8e314ac8d755ad96811f9fbc304a5b3ba4e05285cc"
platform = reference / "node_modules/@typescript/typescript-linux-x64"
assert lock["packages"]["node_modules/@typescript/typescript-linux-x64"]["version"] == json.loads((platform / "package.json").read_text())["version"] == "7.0.2"
assert hashlib.sha256((platform / "lib/tsc").read_bytes()).hexdigest() == "4f2de678286401759b3fb4475bafe35b8f32b4b3a07d92642bbf37eadc9b34a4"
def package_tree_digest(package):
    digest = hashlib.sha256()
    for path in sorted(file for file in package.rglob("*") if file.is_file()):
        digest.update(str(path.relative_to(package)).encode() + b"\0" +
                      hashlib.sha256(path.read_bytes()).digest() + b"\n")
    return digest.hexdigest()


platform_tree = package_tree_digest(platform)
assert platform_tree == "3d2b5d2ccb76b050cc51c61850d41cda203800774b1dedfa3dd4f037efb2a442"
print(json.dumps({"compiler": "typescript", "version": installed_compiler["version"],
                  "compiler_sha256": hashlib.sha256((platform / "lib/tsc").read_bytes()).hexdigest(),
                  "compiler_tree_sha256": platform_tree}), flush=True)
subprocess.run([str(node), str(reference / "node_modules/typescript/bin/tsc"),
                "-p", "tsconfig.workspace.json"], cwd=snapshot, check=True)
expected_generated = {
    "workspace-secure-agent.js": "2ab11378c3e3754243877b5ca7a161f782f35e37d4552fada8a8c018a9ae9b26",
    "workspace-secure-client.js": "630ed5ca5778bf5f6be777246fc1fefc18ede27056c78f20f31113070244f854",
    "protocol-package.js": "c864257535bd3f63128d4c943356fa36f84381244ca980531727abee3b60466a",
    "protocol-package-closure.js": "6ff03ece18806633775fc1dd46bcb5915dc31dd75bfa6ee9cc4255bc47b1761b",
    "workspace-protocol-package-source.js": "3c069458b5c2c7d09f3d7d179a5d215b651b47c8fc43bd8b045fdd5db58f2681",
}
for name, digest in expected_generated.items():
    assert hashlib.sha256((snapshot / "dist-workspace/src" / name).read_bytes()).hexdigest() == digest
assert "stagePackageMaterial" in (snapshot / "dist-workspace/src/workspace-secure-agent.js").read_text()
print(json.dumps({"generated_modules": expected_generated}), flush=True)
def generated_tree_digest(directory):
    files = sorted(directory.rglob("*.js"))
    digest = hashlib.sha256()
    for path in files:
        digest.update(str(path.relative_to(directory)).encode() + b"\0" +
                      hashlib.sha256(path.read_bytes()).digest() + b"\n")
    return len(files), digest.hexdigest()


expected_generated_tree = (204, "e45fa95c3f7ae25723f8175dd471b662020d81266db34fa96b12133fe4bf1afb")
assert generated_tree_digest(snapshot / "dist-workspace/src") == expected_generated_tree
assert generated_tree_digest(reference / "dist-workspace/src") == expected_generated_tree
print(json.dumps({"generated_tree_sha256": expected_generated_tree[1],
                  "generated_files": expected_generated_tree[0]}), flush=True)
imports = re.compile(r"(?:from\s+|import\s*\(|require\s*\()\s*['\"]([^'\"]+)['\"]")
external = {target for module in (snapshot / "dist-workspace/src").rglob("*.js")
            for target in imports.findall(module.read_text())
            if not target.startswith(".") and not target.startswith("node:")}
assert external == {"/assets/markdown-it-15.0.2.mjs", "@hono/node-server",
                    "@hono/node-server/conninfo", "@noble/hashes/sha2.js",
                    "hono", "hono/secure-headers", "hpke", "markdown-it", "zod"}
runtime_packages = {
    "@hono/node-server": ("2.1.1", "19ab65bd4af5760742ef3d0167f1a2222d4c497820f6d78ecddbb4b5e3bff9e5"),
    "@noble/hashes": ("2.3.0", "51193301bbab315479d4f62f9acd3d07226b82f5e32adf656b8d019ad7329c3f"),
    "argparse": ("3.0.2", "2b55049f5d0c9f2734e0ef15a699f51ebf4dc4f0cd81dda3b1f4b2fb54e22b92"),
    "entities": ("8.1.0", "0f7922635c2cd7364585301ea3465c9b3d7143b0d4d699ea19fb62063462089f"),
    "hono": ("4.13.7", "ced74e891039c7a416bc51c33aff46b2f8b5294f4f914ce059cdd14cca7ef8eb"),
    "hpke": ("1.1.7", "9defc948ae1ea662cfbc6142aee97f48e80f5e841fdd21f6f60d865a9cd7a302"),
    "linkify-it": ("6.1.0", "9765ae32fb97f9881d349045c8f12c2b287f38f9938a809268231a81bd451369"),
    "markdown-it": ("15.0.2", "fb471a9368a39fc4d59f80f687a7e512c04e45fbe6da366358e5967978993f21"),
    "mdurl": ("2.1.0", "a21792d7a4a14a9fba44a984d70cd48eb4e12556a04642f4f77c244a0e5f75bf"),
    "punycode.js": ("2.3.1", "c9e0d34059f2f688062541b570cccc60531815cb91bb3f44d2630efb36ba8707"),
    "uc.micro": ("3.0.0", "99b6a5ba7d1ae3ae775a19f0613781e62548b11a385f3791e6e1d173e3921961"),
    "zod": ("4.5.4", "8d97ea5d26672b2aa5790d907e911b7278b68bbd0912d3dfe1142fef62f0e9a8"),
}
for name, (version, digest) in runtime_packages.items():
    package = reference / "node_modules" / name
    metadata = json.loads((package / "package.json").read_text())
    assert lock["packages"]["node_modules/" + name]["version"] == metadata["version"] == version
    assert set(metadata.get("dependencies", {})) | set(metadata.get("peerDependencies", {})) <= set(runtime_packages)
    assert package_tree_digest(package) == digest
print(json.dumps({"runtime_imports": sorted(external), "runtime_package_tree_sha256":
                  {name: digest for name, (_, digest) in runtime_packages.items()}}), flush=True)
env = dict(os.environ, PEERWORK_REFERENCE_ROOT=str(reference), PEERWORK_TEST_STATE=str(state),
           PEERWORK_TEST_FIRST_POST_MODE="normal")
server = subprocess.Popen([str(node), str(source / "tests/reference-kernel-server.mjs")],
                          cwd=source, env=env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
try:
    first = server.stdout.readline()
    assert first, f"reference service did not start: {server.stderr.read()[-800:]}"
    upstream = json.loads(first)["origin"]
    barrier_path = source / "tests/multipart-orphan-post-barrier.py"
    assert hashlib.sha256(barrier_path.read_bytes()).hexdigest() == os.environ["PEERWORK_TEST_BARRIER_SHA256"]
    module_spec = importlib.util.spec_from_file_location("orphan_post_barrier", barrier_path)
    barrier_module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(barrier_module)
    barrier, origin = barrier_module.start_barrier(upstream)
    from threading import Thread
    barrier_thread = Thread(target=barrier.serve_forever, daemon=True)
    barrier_thread.start()
    database = state / "control.sqlite"
    old_dir = state / "legacy-orphan"
    produced = subprocess.run([str(node), str(source / "tests/legacy-owner-source.mjs"),
                               origin, str(old_dir), str(snapshot),
                               "stage-marker-multipart-orphan-index1"],
                              cwd=source, env=env, capture_output=True, text=True, timeout=120)
    assert produced.returncode == 0, produced.stderr[-800:]
    exported = json.loads(produced.stdout)
    assert exported["visibility"] == "PRIVATE" and exported["structure_mode"] == "STRUCTURED"
    assert exported["stage_marker"]["part_index"] == 1
    assert exported["stage_part_count"] >= 3 and exported["pending_count"] == 0
    assert exported["stage_applied"] is False
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        workspace_count = connection.execute(
            "SELECT count(*) FROM secure_commits WHERE workspace_id=?",
            (exported["workspace_id"],)).fetchone()[0]
        command_count = connection.execute(
            "SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?",
            (exported["workspace_id"], exported["stage_marker"]["command_id"])).fetchone()[0]
    assert (workspace_count, command_count) == (2, 0)
    for key in ("state_path", "intent_db_path", "pem_path"):
        path = Path(exported[key])
        assert path.is_relative_to(old_dir) and path.is_file()
        exported[key] = str(guest_state / path.relative_to(state))
    (state / "host-fixture.json").write_text(json.dumps({"origin": origin, "source": exported}))
    print(json.dumps({"fixture": "host", "origin": origin,
                      "mode": "stage-marker-multipart-orphan-index1",
                      "state_path": str(guest_state), "source_paths": "mapped into rootfs"}), flush=True)
    subprocess.run(["bash", str(Path(__file__).with_name("run-installed-historical-multipart-orphan-consumer.sh")), str(rootfs)], check=True)
finally:
    if "barrier" in locals():
        barrier.shutdown()
        barrier.server_close()
        barrier_thread.join(timeout=10)
    server.terminate()
    server.wait(timeout=10)
