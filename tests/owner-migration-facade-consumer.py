"""Installed Python facade only; source and config are caller-selected."""
import json
import sys
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
    if sys.argv[3:] == ["--remove-synthetic-source"]:
        directory = Path(source["protected_ts_state_path"]).parent
        assert directory.name.startswith("facade-")
        directory.rename(directory.with_name(directory.name + "-removed"))
    resumed = peerwork.SecureOwnerWorkspaceClient(**config).resume_attachment(attached["attach_id"])
    read = peerwork.SecureOwnerWorkspaceClient(**config).read(source["workspace_id"])
    assert resumed["status"] == "ATTACHED"
    print(json.dumps({"status": attached["status"], "workspace_id": read["workspace_id"],
                      "sequence": read["sequence"], "head": read["head"]}))
