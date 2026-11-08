"""Installed Python facade only; source and config are caller-selected."""
import json
import sys
import asyncio
from pathlib import Path
import peerwork

config, source = (json.loads(Path(p).read_text()) for p in sys.argv[1:3])
owner = peerwork.SecureOwnerWorkspaceClient(**config)
try:
    attached = owner.attach(**source)
except peerwork.OwnerWorkspaceError as error:
    assert owner.attachments() == []
    print(json.dumps({"code": error.code, "attachments": 0}))
else:
    assert attached["status"] == "ATTACHED"
    if "--remove-synthetic-source" in sys.argv[3:]:
        directory = Path(source["protected_ts_state_path"]).parent
        assert directory.name.startswith("facade-")
        directory.rename(directory.with_name(directory.name + "-removed"))
    resumed = peerwork.SecureOwnerWorkspaceClient(**config).resume_attachment(attached["attach_id"])
    read = peerwork.SecureOwnerWorkspaceClient(**config).read(source["workspace_id"])
    assert resumed["status"] == "ATTACHED"
    result = {"status": attached["status"], "workspace_id": read["workspace_id"],
              "sequence": read["sequence"], "head": read["head"]}
    if "--check-coordination" in sys.argv[3:]:
        markers = resumed["coordination_intents"]
        assert sum(m["status"] == "ARCHIVED_COMPLETED" for m in markers) == 4
        pending = [m for m in markers if m["status"] == "RETAINED_UNRESOLVED"]
        assert len(pending) == 1
        marker = pending[0]
        try:
            owner.retire_coordination_intent(attached["attach_id"], marker["marker_key"], "0" * 64)
            raise AssertionError("wrong hash was accepted")
        except peerwork.OwnerWorkspaceError as error:
            assert error.code == "ATTACH_CONFLICT"
        owner.retire_coordination_intent(attached["attach_id"], marker["marker_key"], marker["input_hash"])
        final = asyncio.run(peerwork.SecureOwnerWorkspaceClient(**config).retire_coordination_intent_async(
            attached["attach_id"], marker["marker_key"], marker["input_hash"]))
        assert sum(m["status"] == "RETIRED_LOCAL" for m in final["coordination_intents"]) == 1
        result["coordination"] = {"archived": 4, "retired": 1, "wrong_hash_refused": True, "async_reopen": True}
    print(json.dumps(result))
