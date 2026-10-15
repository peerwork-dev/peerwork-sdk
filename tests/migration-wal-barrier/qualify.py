"""Tiny isolated qualification of the metadata-only own-child WAL barrier."""
import json
import os
from pathlib import Path
import sys
import tempfile

from trace import run_child

HERE = Path(__file__).resolve().parent
PYTHON = sys.executable


def run(case, mode, expected_hit):
    case.mkdir(mode=0o700)
    backup = case / "backup.snapshot"
    wal = case / "native.sqlite-wal"
    selected_backup = backup.with_name("backup.not-selected") if mode == "wrong-backup" else backup
    argv = [PYTHON, str(HERE / "dummy.py"), str(backup), str(wal), mode]
    result = run_child(argv, dict(os.environ), str(selected_backup), str(wal), stop_at_payload=True)
    assert result["boundary_reached"] is expected_hit, result
    assert result["exit_code"] == (-9 if expected_hit else 0), result
    assert result["armed_by_backup_fsync"] is (mode != "wrong-backup"), result
    for event in result["events"]:
        assert not any(k in event for k in ("buffer", "payload", "data", "bytes")), event
    return result


with tempfile.TemporaryDirectory(prefix="t076-wal-barrier-") as temp:
    root = Path(temp)
    positive = run(root / "positive", "positive", True)
    wrong_backup = run(root / "wrong-backup", "wrong-backup", False)
    short_payload = run(root / "short-payload", "short-payload", False)
    prearm_headers = run(root / "prearm-headers", "prearm-headers", False)
    summary = {"result": "PASS", "scope": "own synchronous Python child; Linux x86_64 syscall metadata only",
               "positive": positive, "wrong_backup_negative": wrong_backup,
               "short_payload_negative": short_payload,
               "prearm_headers_negative": prearm_headers,
               "write_buffers_read": False, "processes_traced": 4}
    print(json.dumps(summary, separators=(",", ":")))
