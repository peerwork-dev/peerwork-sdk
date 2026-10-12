"""Opt-in installed clients against an actual TS-created mixed-actor store."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.request

import peerwork

ROOT = Path(__file__).resolve().parents[1]
NODE = os.environ["PEERWORK_TEST_NODE"]
REFERENCE = os.environ["PEERWORK_REFERENCE_ROOT"]
CLI = os.environ["PEERWORK_TEST_CLI"]
ADDON = Path(os.environ["PEERWORK_TEST_NODE_ADDON"])
WHEEL = Path(os.environ["PEERWORK_TEST_WHEEL"])
SOURCE_COMMIT = os.environ["PEERWORK_TEST_SOURCE_COMMIT"]
assert subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() == SOURCE_COMMIT

started = time.monotonic()
stages = []


def mark(name):
    stages.append({"stage": name, "elapsed_ms": round((time.monotonic() - started) * 1000)})


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def node(source, *args):
    return json.loads(subprocess.check_output([NODE, "-e", source, *map(str, args)], text=True, timeout=30))


def counts(origin):
    with urllib.request.urlopen(origin + "__test/counts", timeout=3) as response:
        return json.load(response)


mark("installed_python_import")
temporary = tempfile.TemporaryDirectory(prefix="peerwork-migration-", dir=ROOT / ".build-target/tmp")
state = Path(temporary.name)
state.chmod(0o700)
env = os.environ.copy()
env.update(PEERWORK_REFERENCE_ROOT=REFERENCE, PEERWORK_TEST_STATE=str(state),
           PEERWORK_TEST_FIRST_POST_MODE="normal")
server = subprocess.Popen([NODE, str(ROOT / "tests/reference-kernel-server.mjs")],
                          cwd=ROOT, env=env, stdout=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, "reference service did not start"
    origin = json.loads(line)["origin"]
    source = json.loads(subprocess.check_output([
        NODE, str(ROOT / "tests/reference-ts-migration-source.mjs"),
        origin, str(state), REFERENCE,
    ], text=True, timeout=30))
    actors = source["actors"]
    assert len(actors) == 2 and len({actor["key_id"] for actor in actors}) == 2
    legacy_db = source["db_path"]
    before = sha(legacy_db)
    assert counts(origin)["commands"] == 2
    mark("actual_ts_client_store_closed")

    identity_a, identity_b = state / "native-A.state", state / "native-B.state"
    public_a = peerwork.import_legacy_identity_pem(str(identity_a), actors[0]["pem_file"])
    assert public_a["key_id"] == actors[0]["key_id"]
    wrong_target = state / "wrong-type.state"
    try:
        peerwork.import_legacy_identity_pem(str(wrong_target), source["wrong_type_pem_file"])
    except RuntimeError:
        pass
    else:
        raise AssertionError("non-Ed25519 PKCS#8 key was accepted")
    assert not wrong_target.exists()
    addon_entry = ADDON.parents[3] / "index.cjs"
    import_b = node("const p=require(process.argv[1]);p.importLegacyIdentityPem(process.argv[2],process.argv[3]).then(v=>console.log(JSON.stringify(v)))",
                    addon_entry, identity_b, actors[1]["pem_file"])
    assert import_b["key_id"] == actors[1]["key_id"]
    journal, backup = state / "native-journal.sqlite", state / "legacy-backup.sqlite"
    signers = [actor["key_id"] for actor in actors]
    client_a = peerwork.KernelClient(origin, str(journal), str(identity_a), allow_loopback_http=True)
    report = client_a.migrate_ts_store(legacy_db, str(backup), signers)
    assert report == {"pending_count": 2, "accepted_count": 2}
    assert backup.exists() and sha(legacy_db) == before
    mark("native_backup_readback_import_verified")

    client_b = peerwork.KernelClient(origin, str(journal), str(identity_b), allow_loopback_http=True)
    assert client_a.status(actors[0]["accepted_id"])["state"] == "ACCEPTED"
    assert client_b.status(actors[1]["accepted_id"])["state"] == "ACCEPTED"
    assert client_a.status(actors[0]["pending_id"])["state"] == "PENDING"
    assert client_b.status(actors[1]["pending_id"])["state"] == "PENDING"
    assert [row["command_id"] for row in client_a.pending()] == [actors[0]["pending_id"]]
    assert [row["command_id"] for row in client_b.pending()] == [actors[1]["pending_id"]]
    mark("both_actors_recovered")

    before_wrong_actor = counts(origin)
    try:
        client_a.submit_saved(actors[1]["pending_id"])
    except RuntimeError:
        pass
    else:
        raise AssertionError("wrong actor submitted a saved legacy command")
    assert counts(origin) == before_wrong_actor
    assert client_b.status(actors[1]["pending_id"])["state"] == "PENDING"
    mark("wrong_actor_refused_without_post")

    node_client = "const p=require(process.argv[1]);p.openKernel({origin:process.argv[2],journalPath:process.argv[3],identityPath:process.argv[4],allowLoopbackHttp:true}).then(async c=>console.log(JSON.stringify(await c.migrateTsStore(process.argv[5],process.argv[6],JSON.parse(process.argv[7])))))"
    assert node(node_client, addon_entry, origin, journal, identity_b, legacy_db, backup,
                json.dumps(signers)) == report
    cli = json.loads(subprocess.check_output([
        CLI, "kernel", "migrate", origin, str(journal), str(identity_a),
        legacy_db, str(backup), "--allow-loopback-http",
        *["--trusted-signer=" + key for key in signers],
    ], text=True, timeout=30))
    assert cli == report and sha(legacy_db) == before
    mark("node_cli_idempotent_import")

    assert client_a.submit_saved(actors[0]["pending_id"])["command_id"] == actors[0]["pending_id"]
    node_submit = "const p=require(process.argv[1]);p.openKernel({origin:process.argv[2],journalPath:process.argv[3],identityPath:process.argv[4],allowLoopbackHttp:true}).then(async c=>console.log(JSON.stringify(await c.submitSaved(process.argv[5]))))"
    assert node(node_submit, addon_entry, origin, journal, identity_b,
                actors[1]["pending_id"])["command_id"] == actors[1]["pending_id"]
    assert counts(origin)["commands"] == 4
    assert counts(origin)["workspaces"] == 4
    assert client_a.status(actors[0]["pending_id"])["state"] == "ACCEPTED"
    assert client_b.status(actors[1]["pending_id"])["state"] == "ACCEPTED"
    assert sha(legacy_db) == before
    mark("both_pending_exact_retries_verified")

    evidence = {
        "kind": "fresh actual TypeScript WorkspaceClient mixed-actor migration to installed native SDK",
        "agent_workflow_compliance": "unverified; scripted business-path run",
        "source_commit": SOURCE_COMMIT,
        "artifact_sha256": {"wheel": sha(WHEEL), "node_addon": sha(ADDON), "cli": sha(CLI)},
        "legacy_source_unchanged": True,
        "actors": 2, "imported_pending": 2, "imported_accepted": 2,
        "service_counts": counts(origin), "stages": stages,
    }
    (ROOT / ".build-artifacts/migration-service-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print("Actual TS-created mixed-actor migration and exact native retry passed")
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
    temporary.cleanup()
