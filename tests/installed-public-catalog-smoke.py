"""Installed anonymous catalog search and exact-digest inspection over pinned HTTP routes."""

import json
import os
from pathlib import Path
import subprocess

import peerwork


SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
NODE = os.environ["PEERWORK_TEST_NODE"]
NODE_PACKAGE = os.environ["PEERWORK_TEST_NODE_PACKAGE"]
CLI = os.environ["PEERWORK_TEST_CLI"]
STATE.mkdir(mode=0o700, parents=True, exist_ok=False)
server_env = dict(os.environ, PEERWORK_SDK_ROOT=str(SOURCE), PEERWORK_TEST_STATE=str(STATE))
server = subprocess.Popen([NODE, str(SOURCE / "tests/reference-catalog-server.mjs")],
                          cwd=SOURCE, env=server_env, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, text=True)
try:
    line = server.stdout.readline()
    assert line, f"catalog fixture did not start: {server.stderr.read()[-800:]}"
    ready = json.loads(line)
    assert ready["bundles"] == 2
    origin = ready["origin"]
    catalog = peerwork.PublicCatalogClient(origin, allow_loopback_http=True)
    listing = catalog.search("", limit=50)
    assert listing["catalog_origin"].rstrip("/") == origin.rstrip("/")
    rows = listing["listing"]["items"]
    assert len(rows) == 2
    vectors = [json.loads((SOURCE / "conformance" / filename).read_text()) for filename in
               ("public-package-vectors.json", "public-package-v2-vectors.json")]
    digests = [vector["package_digest"] for vector in vectors]
    assert {row["bundle_digest"] for row in rows} == set(digests)
    first = catalog.inspect_exact(digests[0])
    assert first["bundle_digest"] == digests[0]
    assert first["summary"]["bundle_digest"] == digests[0]
    assert "release.lock.json" in first["bundle_canonical_json"]

    env = dict(os.environ, PEERWORK_TEST_CATALOG_ORIGIN=origin,
               PEERWORK_TEST_CATALOG_DIGEST=digests[1])
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const catalog = sdk.openPublicCatalog({origin:process.env.PEERWORK_TEST_CATALOG_ORIGIN,allowLoopbackHttp:true});
  const value = await catalog.inspectExact(process.env.PEERWORK_TEST_CATALOG_DIGEST);
  console.log(JSON.stringify(value));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    node = subprocess.run([NODE, "-e", code], env=env, capture_output=True, text=True, timeout=30)
    assert node.returncode == 0, node.stderr[-1200:]
    second = json.loads(node.stdout)
    assert second["bundle_digest"] == digests[1]
    assert second["summary"]["bundle_digest"] == digests[1]
    assert "release.lock.json" in second["bundle_canonical_json"]

    config_file = STATE / "catalog-config.json"
    config_file.write_text(json.dumps(dict(origin=origin, allow_loopback_http=True)))
    cli = subprocess.run([CLI, "secure", "catalog-search", str(config_file), ""],
                         capture_output=True, text=True, timeout=30)
    assert cli.returncode == 0, cli.stderr[-1200:]
    cli_listing = json.loads(cli.stdout)
    assert {row["bundle_digest"] for row in json.loads(cli_listing["listing_canonical_json"])["items"]} == set(digests)

    for _ in range(2):
        try:
            catalog.inspect_exact(digests[0])
        except peerwork.PublicCatalogError as error:
            assert error.code == "CATALOG_DIGEST_MISMATCH", error.code
        else:
            raise AssertionError("tampered or swapped exact package was accepted")
    try:
        catalog.inspect_exact(digests[0].upper())
    except peerwork.PublicCatalogError as error:
        assert error.code == "CATALOG_INPUT_INVALID", error.code
    else:
        raise AssertionError("uppercase digest was accepted")
    constrained = peerwork.PublicCatalogClient(origin, allow_loopback_http=True, max_listing_bytes=1)
    try:
        constrained.search("")
    except peerwork.PublicCatalogError as error:
        assert error.code == "CATALOG_RESOURCE_LIMIT", error.code
    else:
        raise AssertionError("oversize listing was accepted")
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)


def fresh_catalog_server(label):
    state = STATE / label
    state.mkdir(mode=0o700)
    env = dict(os.environ, PEERWORK_SDK_ROOT=str(SOURCE), PEERWORK_TEST_STATE=str(state))
    process = subprocess.Popen([NODE, str(SOURCE / "tests/reference-catalog-server.mjs")],
                               cwd=SOURCE, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, text=True)
    line = process.stdout.readline()
    assert line, f"{label} catalog fixture did not start: {process.stderr.read()[-800:]}"
    ready = json.loads(line)
    assert ready["bundles"] == 2
    return process, ready["origin"]


node_server, node_origin = fresh_catalog_server("node")
try:
    env = dict(os.environ, PEERWORK_TEST_CATALOG_ORIGIN=node_origin,
               PEERWORK_TEST_CATALOG_DIGESTS=json.dumps(digests))
    code = r'''
void (async () => {
  const sdk = require(process.env.PEERWORK_TEST_NODE_PACKAGE);
  const digests = JSON.parse(process.env.PEERWORK_TEST_CATALOG_DIGESTS);
  const catalog = sdk.openPublicCatalog({origin:process.env.PEERWORK_TEST_CATALOG_ORIGIN,allowLoopbackHttp:true});
  const listing = await catalog.search('');
  if(JSON.stringify(listing.listing.items.map(x=>x.bundle_digest).sort())!==JSON.stringify([...digests].sort())) throw Error('Node listing mismatch');
  for(const digest of digests){
    const found = await catalog.inspectExact(digest);
    if(found.bundle_digest!==digest || found.summary.bundle_digest!==digest) throw Error('Node exact inspect mismatch');
  }
  async function refused(action, code){
    try{await action();}catch(error){if(error.code===code)return;throw error;}
    throw Error('Node accepted invalid catalog response');
  }
  await refused(()=>catalog.inspectExact(digests[0]),'CATALOG_DIGEST_MISMATCH');
  await refused(()=>catalog.inspectExact(digests[0]),'CATALOG_DIGEST_MISMATCH');
  await refused(()=>catalog.inspectExact(digests[0].toUpperCase()),'CATALOG_INPUT_INVALID');
  const tiny = sdk.openPublicCatalog({origin:process.env.PEERWORK_TEST_CATALOG_ORIGIN,allowLoopbackHttp:true,maxListingBytes:1});
  await refused(()=>tiny.search(''),'CATALOG_RESOURCE_LIMIT');
  console.log(JSON.stringify({interface:'Node',status:'PASS'}));
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run([NODE, "-e", code], env=env, capture_output=True, text=True, timeout=45)
    assert result.returncode == 0, result.stderr[-1200:]
    assert json.loads(result.stdout) == {"interface": "Node", "status": "PASS"}
finally:
    node_server.terminate()
    try:
        node_server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        node_server.kill()
        node_server.wait(timeout=5)


cli_server, cli_origin = fresh_catalog_server("cli")
try:
    config = STATE / "cli-catalog.json"
    config.write_text(json.dumps(dict(origin=cli_origin, allow_loopback_http=True)))

    def command(verb, config_file, argument):
        return subprocess.run([CLI, "secure", verb, str(config_file), argument],
                              capture_output=True, text=True, timeout=30)

    listing = command("catalog-search", config, "")
    assert listing.returncode == 0, listing.stderr[-1000:]
    assert {row["bundle_digest"] for row in json.loads(json.loads(listing.stdout)["listing_canonical_json"])["items"]} == set(digests)
    for digest in digests:
        inspected = command("catalog-inspect", config, digest)
        assert inspected.returncode == 0, inspected.stderr[-1000:]
        value = json.loads(inspected.stdout)
        assert value["bundle_digest"] == digest
        assert json.loads(value["summary_canonical_json"])["bundle_digest"] == digest
    for _ in range(2):
        refused = command("catalog-inspect", config, digests[0])
        assert refused.returncode != 0 and json.loads(refused.stderr)["code"] == "CATALOG_DIGEST_MISMATCH", refused.stderr[-1000:]
    refused = command("catalog-inspect", config, digests[0].upper())
    assert refused.returncode != 0 and json.loads(refused.stderr)["code"] == "CATALOG_INPUT_INVALID", refused.stderr[-1000:]
    tiny_config = STATE / "cli-catalog-tiny.json"
    tiny_config.write_text(json.dumps(dict(origin=cli_origin, allow_loopback_http=True, max_listing_bytes=1)))
    refused = command("catalog-search", tiny_config, "")
    assert refused.returncode != 0 and json.loads(refused.stderr)["code"] == "CATALOG_RESOURCE_LIMIT", refused.stderr[-1000:]
finally:
    cli_server.terminate()
    try:
        cli_server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        cli_server.kill()
        cli_server.wait(timeout=5)

print(json.dumps(dict(status="PASS", anonymous_catalog=True, digests=digests,
                      installed_interfaces=["Python", "Node", "CLI"],
                      per_interface_search_inspect_and_refusals=True)))
