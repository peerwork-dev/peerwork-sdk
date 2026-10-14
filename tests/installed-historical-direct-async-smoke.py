"""Two frozen installed Python async cases; native calls are never mocked."""
import asyncio
import contextlib
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time
import urllib.request
from urllib.parse import urlsplit

import peerwork

SOURCE = Path(os.environ["PEERWORK_TEST_SDK_ROOT"])
STATE = Path(os.environ["PEERWORK_TEST_STATE"])
for relative, key in (
    ("crates/runtime/src/secure_owner_attach.rs", "PEERWORK_TEST_ATTACH_SOURCE_SHA256"),
    ("tests/legacy-owner-install-intent.mjs", "PEERWORK_TEST_LEGACY_HELPER_SHA256"),
    ("tests/reference-kernel-server.mjs", "PEERWORK_TEST_REFERENCE_FIXTURE_SHA256"),
):
    assert hashlib.sha256((SOURCE / relative).read_bytes()).hexdigest() == os.environ[key]
fixture = json.loads(Path(os.environ["PEERWORK_TEST_HOST_FIXTURE_JSON"]).read_text())
origin = fixture["origin"]
assert origin.startswith("http://127.0.0.1:") and STATE.stat().st_mode & 0o077 == 0
assert len(fixture["sources"]) == 2
assert {item["mode"] for item in fixture["sources"]} == {
    "direct-completed-end", "direct-end-before-post"}
assert all(item["interface"] == "python-async" for item in fixture["sources"])
database = STATE / "control.sqlite"
request_log = Path(fixture["request_log"])
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def service_count(workspace, command=None):
    # Operator oracle: reference-service SQLite only, never native SDK storage.
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        if command is None:
            return connection.execute("SELECT count(*) FROM secure_commits WHERE workspace_id=?",
                                      (workspace,)).fetchone()[0]
        return connection.execute("SELECT count(*) FROM secure_commits WHERE workspace_id=? AND command_id=?",
                                  (workspace, command)).fetchone()[0]


def observed(workspace):
    rows = [json.loads(line) for line in request_log.read_text().splitlines()[fixture["fixture_request_lines"]:]]
    return [row for row in rows if row["host"] == urlsplit(origin).netloc
            and row["path"] == f"/api/workspace/v1/secure/workspaces/{workspace}/commits"]


def hook(path, post=False):
    request = urllib.request.Request(origin.rstrip("/") + path,
                                    data=b"{}" if post else None,
                                    method="POST" if post else "GET")
    with opener.open(request, timeout=5) as response:
        return json.load(response)


def input_for(item):
    return dict(workspace_id=item["workspace_id"],
                protected_ts_state_path=item["state_path"],
                protected_ts_intent_db_path=item["intent_db_path"],
                protected_owner_pkcs8_path=item["pem_path"],
                expected_owner_actor_id=item["owner_actor_id"],
                expected_owner_key_id=item["owner_key_id"])


async def cancel_after_applied_end(owner, item, attach_id):
    assert await asyncio.to_thread(hook, "/__test/delay-next-post", True) == {"enabled": True}
    task = asyncio.create_task(owner.recover_pending_direct_install_packet_async(
        attach_id, item["pending_command_id"]))
    try:
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            status = await asyncio.to_thread(hook, "/__test/post-delay-status")
            if status["started"]:
                assert service_count(item["workspace_id"], item["pending_command_id"]) == 1
                assert service_count(item["workspace_id"]) == 3
                assert not task.done(), "response was delivered before controlled cancellation"
                break
            assert not task.done(), "recovery returned before the after-apply barrier"
            await asyncio.sleep(0.025)
        else:
            raise AssertionError("selected END did not reach the after-apply response barrier")
        task.cancel()
        await asyncio.sleep(0)
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=30)
        except asyncio.CancelledError:
            pass
        else:
            raise AssertionError("cancelled caller received a recovery result")
        assert task.cancelled()
    finally:
        if not task.done():
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=30)


async def main():
    for item in fixture["sources"]:
        completed = item["mode"] == "direct-completed-end"
        workspace = item["workspace_id"]
        native = STATE / ("native-" + item["fixture_dir"])

        def reopen():
            return peerwork.SecureOwnerWorkspaceClient(origin, str(native), allow_loopback_http=True)

        owner = reopen()
        options = Path(item["options_path"]).read_text()
        material = Path(item["material_path"]).read_text()
        selected = input_for(item)
        assert await owner.attachments_async() == []
        if completed:
            assert item["latest_sequence"] == 3 and service_count(workspace) == 3
            inventory = await owner.inspect_completed_direct_install_async(
                **selected, selected_instance_id=item["instance_id"], options_json=options, material_json=material)
            assert inventory["status"] == "COMPLETED_IN_SIGNED_REPLAY"
            assert inventory["begin_command_id"] == item["historical_begin_command_id"]
            assert inventory["begin_commit_hash"] == item["historical_begin_commit_hash"]
            assert inventory["end_sequence"] == 3 and inventory["protocol_digest"] == item["protocol_digest"]
            progress = await owner.attach_completed_direct_install_async(
                **selected, selected_instance_id=item["instance_id"],
                expected_ts_state_digest=inventory["ts_state_digest"], options_json=options, material_json=material)
            assert progress["status"] == "ATTACHED" and progress["pending_direct_install_status"] == "ACCEPTED"
        else:
            assert item["latest_sequence"] == 2 and service_count(workspace) == 2
            assert service_count(workspace, item["pending_command_id"]) == 0
            inventory = await owner.inspect_pending_direct_install_packet_async(
                **selected, selected_command_id=item["pending_command_id"], options_json=options, material_json=material)
            assert inventory["status"] == "PENDING_UNRESOLVED"
            assert inventory["command_id"] == item["pending_command_id"]
            assert inventory["original_commit_hash"] == item["pending_commit_hash"]
            progress = await owner.attach_pending_direct_install_packet_async(
                **selected, selected_command_id=item["pending_command_id"],
                expected_ts_state_digest=inventory["ts_state_digest"], options_json=options, material_json=material)
            assert progress["status"] == "ATTACHED_RESTRICTED"
            assert progress["pending_direct_install_status"] == "BEGIN_ACCEPTED_CONTINUATION_PENDING"
        assert inventory["instance_id"] == item["instance_id"] and inventory["intent_hash"] == item["intent_hash"]
        assert len(inventory["ts_state_digest"]) == 64
        assert observed(workspace) == []
        attach_id = progress["attach_id"]
        fresh = reopen()
        assert await fresh.attachments_async() == [progress]
        if not completed:
            old = STATE / item["fixture_dir"]
            shutil.move(str(old), str(STATE / (item["fixture_dir"] + "-removed")))
            for key in ("state_path", "pem_path", "intent_db_path", "options_path", "material_path"):
                assert not Path(item[key]).exists()
            # Do not pass source paths, options or material to recovery.
            assert await fresh.resume_attachment_async(attach_id) == progress
            await cancel_after_applied_end(fresh, item, attach_id)
            fresh = reopen()
            history = await fresh.attachments_async()
            assert len(history) == 1 and history[0]["attach_id"] == attach_id
            assert history[0]["status"] == "ATTACHED_RESTRICTED"
            assert history[0]["pending_direct_install_command_id"] == item["pending_command_id"]
            resumed = await fresh.resume_attachment_async(attach_id)
            assert resumed["status"] == "ATTACHED_RESTRICTED" and resumed["sequence"] == 3
            progress = await fresh.recover_pending_direct_install_packet_async(attach_id, item["pending_command_id"])
            assert progress["status"] == "ATTACHED" and progress["pending_direct_install_status"] == "ACCEPTED"
            assert service_count(workspace, item["pending_command_id"]) == 1
            recorded = observed(workspace)
            assert len(recorded) == 1 and recorded[0]["command_id"] == item["pending_command_id"]
            assert {key:recorded[0][key] for key in ("method", "path", "body_sha256")} == item["expected_native_request"]
            with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
                assert connection.execute("SELECT commit_hash FROM secure_commits WHERE workspace_id=? AND command_id=?",
                    (workspace, item["pending_command_id"])).fetchone()[0] == item["pending_commit_hash"]
            assert await reopen().recover_pending_direct_install_packet_async(attach_id, item["pending_command_id"]) == progress
        assert await reopen().resume_attachment_async(attach_id) == progress
        readback = await reopen().read_async(workspace)
        assert readback["sequence"] == 3 and readback["structure_status"] == "ACTIVE"
        assert any(row["kind"] == "instances" and row["id"] == item["instance_id"]
            and row["value"]["protocol_digest"] == item["protocol_digest"]
            and row["value"]["origin_entrypoint"] == item["entrypoint"] for row in readback["objects"])
        assert any(row["kind"] == "protocols" and row["id"] == item["protocol_digest"] for row in readback["objects"])
        assert await reopen().private_package_installer(workspace).installs_async() == []
        assert await reopen().attachments_async() == [progress]
        assert service_count(workspace) == 3
        assert len(observed(workspace)) == (0 if completed else 1)
        print(json.dumps({"interface":"python-async", "mode":item["mode"],
            "status":progress["status"], "sequence":3, "native_commit_posts":0 if completed else 1,
            "source_removed":not completed, "cancellation_disposition":"not cancelled" if completed else "CancelledError after selected END applied; fresh exact recovery accepted"}), flush=True)
    print("installed Python async completed-map and cancelled source-gone END recovery PASS", flush=True)


asyncio.run(main())
