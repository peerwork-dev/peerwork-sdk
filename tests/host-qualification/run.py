#!/usr/bin/env python3
"""Run installed Peerwork host qualification with synthetic state and no network egress."""

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote

import agy


SUITE = Path(__file__).resolve().parent
SDK = SUITE.parent.parent
CASES = {
    "receiving-reconnect": (
        "compact_receiving_falls_back_and_resumes_after_socket_failure", (), ()
    ),
    "codex-restart": (
        "codex_handoff_launch_and_same_thread_restart", ("codex",), ()
    ),
    "codex-opencode": (
        "independent_managed_codex_and_opencode_sessions",
        ("codex", "opencode"), ("HANDOFF-1", "OPEN-1", "OPEN-2")
    ),
    "codex-agy": (
        "independent_managed_codex_and_agy_sessions",
        ("codex", "agy"), ("HANDOFF-1", "AGY-1", "AGY-2")
    ),
}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def stop_group(child):
    if child.poll() is not None:
        return
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(child.pid, signal.SIGKILL)
        child.wait(timeout=5)


def start(stack, command, env, log, cwd=None):
    stream = stack.enter_context(log.open("w"))
    child = subprocess.Popen(
        command, env=env, cwd=cwd, stdin=subprocess.DEVNULL,
        stdout=stream, stderr=subprocess.STDOUT, start_new_session=True,
    )
    stack.callback(stop_group, child)
    return child


def await_ready(child, check):
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if child.poll() is not None:
            raise RuntimeError("owned fixture exited before readiness")
        if check():
            return
        time.sleep(0.05)
    raise RuntimeError("owned fixture readiness timed out")


def enable_loopback():
    if [name for _, name in socket.if_nameindex()] != ["lo"]:
        raise RuntimeError("host qualification must run in an isolated network namespace")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as control:
        fcntl.ioctl(control, 0x8914, struct.pack("16sH22x", b"lo", 1))


def model_config(args, root, env, stack, harnesses):
    if "codex" in harnesses:
        port_file = root / "codex-port"
        model = start(stack, [sys.executable, SUITE / "codex-model.py", port_file],
                      env, root / "codex-model.log")
        await_ready(model, lambda: port_file.exists() and port_file.stat().st_size > 0)
        codex_home = root / "codex"
        codex_home.mkdir()
        env["CODEX_HOME"] = env["PEERWORK_TEST_CODEX_HOME"] = str(codex_home)
        (codex_home / "config.toml").write_text(
            'model = "fixture"\nmodel_provider = "fixture"\napproval_policy = "never"\n'
            '[model_providers.fixture]\nname = "Fixture"\n'
            f'base_url = "http://127.0.0.1:{int(port_file.read_text())}/v1"\n'
            'wire_api = "responses"\nrequires_openai_auth = false\n'
            '[features]\nincremental_tools = false\nincremental_tools_legacy = false\n'
            'plugins = false\nremote_plugin = false\n'
        )
    if not {"opencode", "agy"}.intersection(harnesses):
        return
    spec = importlib.util.spec_from_file_location(
        "opencode_qualification", SDK / "tests/qualify-opencode-v2.py")
    fixture = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixture)
    if "agy" in harnesses:
        output = root / "agy-model"
        output.mkdir()
        agy_model = fixture.Model(output)
        stack.callback(agy_model.server_close)
        agy.prepare(args.agy, root, env, stack, agy_model)
    if "opencode" not in harnesses:
        return
    project = root / "opencode-project"
    settings = project / ".opencode/opencode.json"
    settings.parent.mkdir(parents=True)
    model = fixture.Model(root)
    stack.callback(model.server_close)
    threading.Thread(target=model.serve_forever, daemon=True).start()
    stack.callback(model.shutdown)
    fixture.atomic(settings, {
        "model": "fixture/fixture", "update": "disable",
        "permissions": [{"action": "*", "resource": "*", "effect": "allow"}],
        "providers": {"fixture": {
            "name": "Synthetic model", "env": ["PEERWORK_FIXTURE_KEY"],
            "package": "@opencode/ai/providers/openai-compatible",
            "settings": {"baseURL": f"http://127.0.0.1:{model.server_port}/v1"},
            "models": {"fixture": {
                "name": "Fixture", "capabilities": {"tools": True},
                "limit": {"context": 128000, "output": 4096},
            }},
        }},
    })
    host_env = dict(env, PEERWORK_FIXTURE_KEY="synthetic-no-paid-provider",
                    OPENCODE_DISABLE_FREE_MODELS="1")
    for kind in ("STATE", "CONFIG", "DATA", "CACHE"):
        path = root / f"opencode-{kind.lower()}"
        path.mkdir()
        host_env[f"XDG_{kind}_HOME"] = str(path)
    registration = Path(host_env["XDG_STATE_HOME"]) / "opencode/service.json"
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    child = start(stack, [args.opencode, "serve", "--service", "--hostname",
                          "127.0.0.1", "--port", str(port)], host_env,
                  root / "opencode.log", cwd=project)

    def registered():
        try:
            return json.loads(registration.read_text())["pid"] == child.pid
        except (OSError, ValueError, KeyError):
            return False

    await_ready(child, registered)
    env["PEERWORK_TEST_OPENCODE_PROJECT"] = str(project)
    env["PEERWORK_TEST_OPENCODE_SERVICE"] = str(registration)


def run_cases(args, case_names, postgres_url):
    enable_loopback()
    with tempfile.TemporaryDirectory(prefix="peerwork-hosts-") as directory:
        root = Path(directory)
        for directory in ("home", "tmp", "bin", "state", "config", "data", "cache"):
            (root / directory).mkdir()
        env = {
            "PATH": f"{root / 'bin'}:/usr/local/bin:/usr/bin:/bin",
            "HOME": str(root / "home"), "TMPDIR": str(root / "tmp"),
            "XDG_STATE_HOME": str(root / "state"), "XDG_CONFIG_HOME": str(root / "config"),
            "XDG_DATA_HOME": str(root / "data"), "XDG_CACHE_HOME": str(root / "cache"),
            "LANG": "C.UTF-8", "RUST_MIN_STACK": "16777216",
            "PEERWORK_SDK_REFERENCE_ROOT": str(SDK),
            "PEERWORK_STRUCTURE_REFERENCE_ROOT": str(args.product),
            "PEERWORK_POSTGRES_TEST_URL": postgres_url,
            "PEERWORK_TEST_NODE": str(args.node), "PEERWORK_PARTICIPANT_CLI": str(args.sdk),
            "PEERWORK_TEST_COMPACT_RECEIVING": "1",
        }
        harnesses = set().union(*(CASES[name][1] for name in case_names))
        for name in sorted(harnesses):
            binary = getattr(args, name)
            if binary is None:
                raise ValueError(f"--{name} is required for this selection")
            (root / "bin" / name).symlink_to(binary)
            version = subprocess.check_output(
                [binary, "--version"], cwd=root, env=env, text=True, timeout=15)
            print(json.dumps({"host": name, "version": version.strip(), "sha256": digest(binary)}),
                  flush=True)

        with contextlib.ExitStack() as stack:
            model_config(args, root, env, stack, harnesses)
            for name in case_names:
                rust_test, _, signed_replies = CASES[name]
                command = [args.runner]
                if args.runner_loader:
                    command = [args.runner_loader, "--library-path", args.runner_libraries, *command]
                command += [rust_test, "--include-ignored", "--nocapture", "--test-threads=1"]
                child = start(stack, command, env, root / f"{name}.log")
                code = child.wait(timeout=240)
                trace = (root / f"{name}.log").read_text(errors="replace")
                observed = tuple(re.findall(r"verified signed reply for ([A-Z0-9-]+)", trace))
                passed = (code == 0 and "test result: ok. 1 passed;" in trace
                          and sorted(observed) == sorted(signed_replies))
                print(json.dumps({"case": name, "state": "PASS" if passed else "FAIL",
                                  "signed_replies": list(observed), "exit_code": code}), flush=True)
                if not passed:
                    print("\n".join(trace.splitlines()[-24:]), file=sys.stderr)
                    return 1
    return 0


def postgres_fixture(args, command):
    with tempfile.TemporaryDirectory(prefix="pwdb-") as directory:
        root = Path(directory)
        port = 5432
        user = args.postgres_user if os.geteuid() == 0 else None
        if user:
            owner = pwd.getpwnam(user)
            os.chown(root, owner.pw_uid, owner.pw_gid)
            root.chmod(0o711)
        run_as = ["/usr/sbin/runuser", "-u", user, "--"] if user else []
        env = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(root)}
        if args.postgres_library_path:
            env["LD_LIBRARY_PATH"] = str(args.postgres_library_path)

        def postgres(tool, *arguments):
            subprocess.run([*run_as, args.postgres_bin / tool, *arguments], check=True,
                           cwd=root, env=env, stdout=subprocess.DEVNULL, timeout=30)

        data = root / "data"
        password = secrets.token_urlsafe(32)
        password_file = root / "password"
        with os.fdopen(os.open(password_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            file.write(password + "\n")
        if user:
            os.chown(password_file, owner.pw_uid, owner.pw_gid)
        try:
            postgres("initdb", "-D", data, "--auth=scram-sha-256", "--no-locale", "-U", "fixture",
                     f"--pwfile={password_file}")
        finally:
            password_file.unlink()
        options = f"-c listen_addresses='' -p {port} -k {root} -c fsync=off -c shared_buffers=8MB"
        postgres("pg_ctl", "-D", data, "-l", root / "server.log", "-o", options, "-w", "start")
        try:
            url = (f"postgresql://fixture:{password}@localhost:{port}/postgres"
                   f"?host={quote(str(root), safe='')}&sslmode=disable")
            return subprocess.run(
                ["unshare", "--user", "--map-root-user", "--net", *command,
                 "--isolated-fixture"],
                env=dict(os.environ, PEERWORK_QUALIFICATION_POSTGRES_URL=url), check=False,
            ).returncode
        finally:
            postgres("pg_ctl", "-D", data, "-m", "fast", "-w", "stop")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("sdk", "runner", "product", "node", "postgres-bin"):
        parser.add_argument("--" + name, type=lambda path: Path(path).resolve(strict=True),
                            required=True)
    for name in ("codex", "opencode", "agy", "postgres-library-path", "runner-loader", "runner-libraries"):
        parser.add_argument("--" + name, type=lambda path: Path(path).resolve(strict=True))
    parser.add_argument("--postgres-user", default="nobody",
                        help="unprivileged fixture owner when the TEST launcher runs as root")
    parser.add_argument("--case", choices=CASES, action="append")
    parser.add_argument("--isolated-fixture", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if bool(args.runner_loader) != bool(args.runner_libraries):
        parser.error("--runner-loader and --runner-libraries must be supplied together")
    selected = list(dict.fromkeys(args.case or CASES))
    for harness in set().union(*(CASES[name][1] for name in selected)):
        if getattr(args, harness) is None:
            parser.error(f"--{harness} is required for the selected cases")
    if args.isolated_fixture:
        return run_cases(args, selected, os.environ["PEERWORK_QUALIFICATION_POSTGRES_URL"])
    print(json.dumps({"suite": "peerwork-host-qualification", "sdk_sha256": digest(args.sdk),
                      "test_runner_sha256": digest(args.runner), "cases": selected}), flush=True)
    return postgres_fixture(args, [sys.executable, __file__, *sys.argv[1:]])


if __name__ == "__main__":
    raise SystemExit(main())
