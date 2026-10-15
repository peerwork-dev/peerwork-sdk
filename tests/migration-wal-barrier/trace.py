"""Own-child Linux/x86_64 fsync/pwrite metadata barrier; never reads write buffers."""
import ctypes
import os
import signal
import struct
import time

PTRACE_TRACEME = 0
PTRACE_CONT = 7
PTRACE_SYSCALL = 24
PTRACE_SETOPTIONS = 0x4200
PTRACE_GET_SYSCALL_INFO = 0x420E
PTRACE_O_TRACESYSGOOD = 0x1
PTRACE_O_EXITKILL = 0x00100000
libc = ctypes.CDLL(None, use_errno=True)
libc.ptrace.restype = ctypes.c_long
libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p]


def ptrace(request, pid, a=0, b=0):
    ctypes.set_errno(0)
    result = libc.ptrace(request, pid, a, b)
    if result == -1 and ctypes.get_errno():
        raise OSError(ctypes.get_errno(), "own-child ptrace")
    return result


def fd_path(pid, fd):
    try:
        return os.readlink(f"/proc/{pid}/fd/{fd}")
    except OSError:
        return None


def run_child(argv, env, backup_path, wal_path, stop_at_payload, timeout=20):
    """Trace only this synchronous child; retain syscall metadata, not buffers."""
    backup_path = os.path.realpath(backup_path)
    wal_path = os.path.realpath(wal_path)
    out = os.fork()
    if out == 0:
        try:
            ptrace(PTRACE_TRACEME, 0)
            os.kill(os.getpid(), signal.SIGSTOP)
            os.execve(argv[0], argv, env)
        except BaseException:
            os._exit(111)

    # Fail closed if procfs exposes a different PID namespace than this
    # tracer. We only inspect self and the child we just forked.
    if os.readlink("/proc/self") != str(os.getpid()) or not os.path.isdir(f"/proc/{out}"):
        try:
            os.kill(out, signal.SIGKILL)
            os.waitpid(out, 0)
        except (ProcessLookupError, ChildProcessError):
            pass
        raise RuntimeError("procfs PID view does not match the own-child tracer namespace")

    events = []
    armed = False
    wal_header_ok = False
    frame_header_ok = False
    pending = None
    hit = False
    started = time.monotonic()
    previous = signal.signal(signal.SIGALRM, lambda *_: (_ for _ in ()).throw(TimeoutError("own child timeout")))
    signal.alarm(timeout)
    try:
        child, status = os.waitpid(out, 0)
        assert child == out and os.WIFSTOPPED(status)
        ptrace(PTRACE_SETOPTIONS, out, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL)
        while True:
            ptrace(PTRACE_SYSCALL, out, 0, 0)
            child, status = os.waitpid(out, 0)
            assert child == out
            if os.WIFEXITED(status):
                return {"pid": out, "exit_code": os.WEXITSTATUS(status), "boundary_reached": hit,
                        "armed_by_backup_fsync": armed, "events": events,
                        "duration_seconds": time.monotonic() - started}
            if os.WIFSIGNALED(status):
                raise AssertionError(f"child signal before requested outcome: {os.WTERMSIG(status)}")
            if os.WSTOPSIG(status) != (signal.SIGTRAP | 0x80):
                continue
            info = ctypes.create_string_buffer(128)
            size = ptrace(PTRACE_GET_SYSCALL_INFO, out, 128, ctypes.addressof(info))
            raw = info.raw
            op = raw[0]
            if op == 1:  # syscall entry
                nr = struct.unpack_from("<Q", raw, 24)[0]
                args = struct.unpack_from("<6Q", raw, 32)
                if nr == 74:  # fsync(fd)
                    pending = ("fsync", args[0], fd_path(out, args[0]))
                elif nr == 18:  # pwrite64(fd, user_buffer, count, offset)
                    fd, count, offset = args[0], args[2], args[3]
                    path = fd_path(out, fd)
                    exact_wal = path == wal_path
                    pending = ("pwrite64", fd, path, count, offset, exact_wal)
                    events.append({"phase": "entry", "syscall": "pwrite64", "fd": fd,
                                   "exact_wal": exact_wal, "offset": offset, "length": count,
                                   "armed": armed, "prior_wal_header": wal_header_ok,
                                   "prior_frame_header": frame_header_ok})
                    if (stop_at_payload and armed and exact_wal and wal_header_ok and frame_header_ok
                            and offset >= 56 and count >= 512):
                        hit = True
                        events.append({"phase": "payload-entry-stop", "syscall": "pwrite64", "fd": fd,
                                       "exact_wal": True, "offset": offset, "length": count,
                                       "armed": True, "prior_wal_header": True,
                                       "prior_frame_header": True})
                        os.kill(out, signal.SIGKILL)
                        child, status = os.waitpid(out, 0)
                        assert child == out and os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGKILL
                        return {"pid": out, "exit_code": -signal.SIGKILL, "boundary_reached": True,
                                "armed_by_backup_fsync": armed, "events": events,
                                "duration_seconds": time.monotonic() - started}
                else:
                    pending = None
            elif op == 2:  # syscall exit
                result = struct.unpack_from("<q", raw, 24)[0]
                if pending and pending[0] == "fsync":
                    matched = pending[2] == backup_path
                    if matched and result == 0:
                        armed = True
                    events.append({"phase": "exit", "syscall": "fsync", "fd": pending[1],
                                   "exact_backup": matched, "return": result, "armed": armed})
                elif pending and pending[0] == "pwrite64":
                    _, fd, _path, count, offset, exact_wal = pending
                    if result > 0 and exact_wal and offset == 0 and count >= 32 and result >= 32:
                        wal_header_ok = True
                    if result > 0 and exact_wal and offset == 32 and count >= 24 and result >= 24:
                        frame_header_ok = True
                    events.append({"phase": "exit", "syscall": "pwrite64", "fd": fd,
                                   "exact_wal": exact_wal, "offset": offset, "length": count,
                                   "return": result, "wal_header_written": wal_header_ok,
                                   "frame_header_written": frame_header_ok})
                pending = None
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)
        try:
            os.kill(out, signal.SIGKILL)
            os.waitpid(out, 0)
        except (ProcessLookupError, ChildProcessError):
            pass
