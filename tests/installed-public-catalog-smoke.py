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
    print(json.dumps(dict(status="PASS", anonymous_catalog=True, digests=digests,
                          installed_interfaces=["Python", "Node", "CLI"],
                          tampered_and_swapped_refused=True)))
finally:
    server.terminate()
    try:
        server.wait(timeout=5)
    except subprocess.TimeoutExpired:
        server.kill()
        server.wait(timeout=5)
