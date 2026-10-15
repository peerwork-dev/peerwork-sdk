"""Public dummy writer for tracer qualification; test bytes contain no secrets."""
import os
import sys

backup, wal, mode = sys.argv[1:]
with open(backup, "wb") as stream:
    stream.write(b"public backup fixture")
    stream.flush()
    os.fsync(stream.fileno())

if mode == "wrong-backup":
    with open(backup + ".other", "wb") as stream:
        stream.write(b"unselected")
        stream.flush()
        os.fsync(stream.fileno())
    active_backup = backup + ".other"
else:
    active_backup = backup

fd = os.open(wal, os.O_CREAT | os.O_RDWR | os.O_TRUNC, 0o600)
try:
    os.pwrite(fd, b"H" * 32, 0)
    os.pwrite(fd, b"F" * 24, 32)
    length = 511 if mode == "short-payload" else 512
    os.pwrite(fd, b"P" * length, 56)
finally:
    os.close(fd)
