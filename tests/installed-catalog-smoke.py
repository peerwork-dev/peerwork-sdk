"""Opt-in installed SDK catalog flow against the pinned actual Peerwork kernel."""

import base64
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
WHEEL = Path(os.environ["PEERWORK_TEST_WHEEL"])
ADDON = Path(os.environ["PEERWORK_TEST_NODE_ADDON"])
CLI = Path(os.environ["PEERWORK_TEST_CLI"])
SOURCE_COMMIT = os.environ["PEERWORK_TEST_SOURCE_COMMIT"]
assert subprocess.check_output(
    ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
).strip() == SOURCE_COMMIT, "SDK source checkout differs from artifact pin"

started = time.monotonic()
stages = []


def mark(stage):
    stages.append({"stage": stage, "elapsed_ms": round((time.monotonic() - started) * 1000)})


def token():
    return base64.urlsafe_b64encode(os.urandom(32)).decode().rstrip("=")


def counts(origin):
    with urllib.request.urlopen(origin + "__test/catalog-counts", timeout=2) as response:
        return json.load(response)


def official_bundle():
    generator = r'''
import {readFileSync,readdirSync} from 'node:fs';
import {join,relative} from 'node:path';
import {pathToFileURL} from 'node:url';
const root=process.argv[1], directory=join(root,'protocols/proposal-adoption');
const files={};
function walk(path){for(const item of readdirSync(path,{withFileTypes:true})){
  const full=join(path,item.name);
  if(item.isDirectory()) walk(full);
  else files[relative(directory,full).split('\\').join('/')]=readFileSync(full,'utf8');
}}
walk(directory);
const pkg=await import(pathToFileURL(join(root,'dist-workspace/src/protocol-package.js')).href);
const bundle={format:'peerwork.protocol-package.v1',files:Object.fromEntries(Object.entries(files).sort(([a],[b])=>a.localeCompare(b)))};
const bytes=Buffer.from(pkg.canonicalProtocolPackageBytes(bundle));
console.log(JSON.stringify({bytes:bytes.toString('base64'),metadata:JSON.parse(files['package.json'])}));
'''
    output = subprocess.check_output(
        [NODE, "--input-type=module", "-e", generator, REFERENCE], text=True, timeout=20,
    )
    value = json.loads(output)
    return base64.b64decode(value["bytes"]), value["metadata"]


def command(info, action, body, *, path="/api/workspace/v1/commands"):
    now = int(time.time() * 1000)
    return dict(
        v=1, audience="reference-kernel", command_id=token(),
        actor_id=info["actor_id"],
        authority=hashlib.sha256(info["actor_id"].encode()).hexdigest(),
        method="POST", path=path, workspace_id=None, instance_id=None,
        protocol_digest=None, action_id=action,
        expected_workspace_revision=None, expected_instance_revision=None,
        exact_input_refs=[], body=body, issued_at=now, expires_at=now + 600_000,
    )


def server_for(state):
    env = os.environ.copy()
    env.update(PEERWORK_REFERENCE_ROOT=REFERENCE, PEERWORK_TEST_STATE=str(state),
               PEERWORK_TEST_CATALOG="1", PEERWORK_TEST_FIRST_POST_MODE="normal")
    process = subprocess.Popen(
        [NODE, str(ROOT / "tests/reference-kernel-server.mjs")],
        cwd=ROOT, env=env, stdout=subprocess.PIPE, text=True,
    )
    line = process.stdout.readline()
    assert line, "reference service did not start"
    return process, json.loads(line)["origin"]


mark("installed_python_import")
bundle, metadata = official_bundle()
bundle_digest = hashlib.sha256(bundle).hexdigest()
assert 0 < len(bundle) <= 1024 * 1024
mark("official_bundle_canonicalized")

temporary = tempfile.TemporaryDirectory(prefix="peerwork-catalog-")
state = Path(temporary.name)
state.chmod(0o700)
server, origin = server_for(state)
try:
    identity = state / "identity.state"
    journal = state / "journal.sqlite"
    info = peerwork.create_identity(str(identity))
    client = peerwork.KernelClient(origin, str(journal), str(identity),
                                   allow_loopback_http=True)
    client.open()

    def issue(action, body, *, path="/api/workspace/v1/commands", chunk=None):
        request = command(info, action, body, path=path)
        pending = client.prepare(request, upload_chunk=chunk)
        assert pending["command_id"] == request["command_id"]
        result = client.submit_saved(request["command_id"])
        assert result["command_id"] == request["command_id"]
        assert client.status(request["command_id"])["state"] == "ACCEPTED"
        return request, result

    issue("identity.register", {})
    _, claimed = issue("catalog.namespace.claim", {"namespace": info["actor_id"]})
    assert claimed["catalog"] == {
        "kind": "namespace_claim", "namespace": info["actor_id"],
    }
    mark("namespace_claim_verified")

    upload_id = token()
    chunks = [bundle[offset:offset + 65_536] for offset in range(0, len(bundle), 65_536)]
    _, begun = issue("catalog.upload.begin", {
        "upload_id": upload_id, "bundle_digest": bundle_digest,
        "total_bytes": len(bundle), "chunk_count": len(chunks),
    })
    assert begun["catalog"]["kind"] == "upload_begin"
    assert begun["catalog"]["upload_id"] == upload_id
    assert begun["catalog"]["state"] == "STAGING"
    mark("upload_begin_verified")

    first = chunks[0]
    bad = command(info, "catalog.upload.chunk", {
        "upload_id": upload_id, "bundle_digest": bundle_digest, "index": 0,
        "offset": 0, "byte_length": len(first),
        "chunk_digest": hashlib.sha256(first).hexdigest(),
    }, path="/api/workspace/v1/catalog/upload")
    try:
        client.prepare(bad, upload_chunk=b"wrong chunk")
        raise AssertionError("mismatched binary chunk was saved")
    except RuntimeError:
        pass
    assert client.status(bad["command_id"])["state"] == "NOT_FOUND"
    mark("mismatched_chunk_refused_before_save")

    received = 0
    for index, chunk in enumerate(chunks):
        _, accepted = issue("catalog.upload.chunk", {
            "upload_id": upload_id, "bundle_digest": bundle_digest,
            "index": index, "offset": received, "byte_length": len(chunk),
            "chunk_digest": hashlib.sha256(chunk).hexdigest(),
        }, path="/api/workspace/v1/catalog/upload", chunk=chunk)
        received += len(chunk)
        assert accepted["catalog"] == {
            "kind": "upload_chunk", "upload_id": upload_id,
            "index": index, "received_bytes": received,
            "state": "READY" if index == len(chunks) - 1 else "STAGING",
        }
    assert received == len(bundle)
    mark("binary_chunks_verified")

    publish, published = issue("catalog.package.publish", {
        "upload_id": upload_id, "bundle_digest": bundle_digest,
        "package_id": metadata["package_id"], "version": metadata["version"],
    })
    assert published["catalog"]["kind"] == "package_publish"
    assert published["catalog"]["namespace"] == info["actor_id"]
    assert published["catalog"]["package_id"] == metadata["package_id"]
    assert published["catalog"]["version"] == metadata["version"]
    assert published["catalog"]["bundle_digest"] == bundle_digest
    assert isinstance(published["catalog"]["published"], int)
    assert len(published["protocol_digest"]) == 64
    mark("published_digest_verified")

    assert client.submit_saved(publish["command_id"]) == published
    assert client.status(publish["command_id"])["result"] == published
    totals = counts(origin)
    assert totals == {
        "commands": 4 + len(chunks), "namespaces": 1, "uploads": 1,
        "ready_uploads": 0, "consumed_uploads": 1, "chunks": 0,
        "packages": 1, "outbox": 1,
    }, totals
    mark("publish_idempotent_after_restart")

    node_code = r'''
const sdk=require('./.build-artifacts/node-consumer/index.cjs');
(async()=>{
 const [origin,journal,identity,id,digest]=process.argv.slice(1);
 const client=await sdk.openKernel({origin,journalPath:journal,identityPath:identity,allowLoopbackHttp:true});
 const status=await client.status(id);
 if(status.state!=='ACCEPTED'||status.result.catalog.bundle_digest!==digest) throw Error('Node catalog status mismatch');
 const replay=await client.submitSaved(id);
 if(replay.catalog.bundle_digest!==digest) throw Error('Node catalog retry mismatch');
 console.log('Node catalog accepted reuse passed');
})().catch(error=>{console.error(error);process.exitCode=1});
'''
    subprocess.run(
        [NODE, "-e", node_code, origin, str(journal), str(identity),
         publish["command_id"], bundle_digest], cwd=ROOT, check=True, timeout=20,
    )
    command_line = [str(CLI), "kernel", "status", origin, str(journal),
                    str(identity), publish["command_id"], "--allow-loopback-http"]
    status = json.loads(subprocess.check_output(command_line, text=True, timeout=15))
    assert status["state"] == "ACCEPTED"
    assert status["result"]["catalog"]["bundle_digest"] == bundle_digest
    assert counts(origin) == totals
    mark("node_cli_recovered_verified_publish")
finally:
    server.terminate()
    server.wait(timeout=5)
    temporary.cleanup()

evidence = {
    "kind": "scripted fresh synthetic actual Peerwork catalog service business path",
    "agent_workflow_compliance": "unverified; this script is not an Agent usability run",
    "source_commit": SOURCE_COMMIT,
    "artifacts_sha256": {
        path.name: hashlib.sha256(path.read_bytes()).hexdigest()
        for path in [WHEEL, ADDON, CLI]
    },
    "official_bundle_sha256": bundle_digest,
    "official_bundle_bytes": len(bundle),
    "chunk_count": len(chunks),
    "stages": stages,
    "service_counts": totals,
}
(ROOT / ".build-artifacts/catalog-service-evidence.json").write_text(
    json.dumps(evidence, indent=2) + "\n"
)
print("Python/Node/CLI actual catalog publish and recovery passed")
