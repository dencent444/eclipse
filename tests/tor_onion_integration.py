"""Exercise real Tor SAFECOOKIE, ADD_ONION, key persistence, and reconnect.

The service never publishes: Tor runs with DisableNetwork=1. Its control
protocol and local listener are still available for deterministic testing.
"""

import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

node_binary = sys.argv[1]
tor_binary = shutil.which("tor")
if tor_binary is None:
    print("tor_onion_integration: skipped (tor executable unavailable)")
    sys.exit(0)

environment = dict(os.environ)
environment["ASAN_OPTIONS"] = "detect_leaks=0"


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def wait_until(predicate, description, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("timed out waiting for " + description)


def ctl(directory, *words):
    result = subprocess.run([node_binary, "ctl", str(directory), *words],
                            capture_output=True, text=True, timeout=8,
                            env=environment)
    assert result.returncode == 0, (result.stdout, result.stderr)
    return result.stdout.strip()


def fields(answer):
    return dict(part.split("=", 1) for part in answer.split() if "=" in part)


with tempfile.TemporaryDirectory(prefix="eclipse-tor-") as root:
    root = pathlib.Path(root)
    data = root / "tor-data"
    data.mkdir(mode=0o700)
    torrc = root / "torrc"
    torrc.write_text("\n")
    cookie = data / "control_auth_cookie"
    node_dir = root / "node"
    control_port = free_port()
    virtual_port = free_port()
    logs = []
    processes = []

    def start_tor():
        log = open(root / "tor.log", "a+")
        logs.append(log)
        process = subprocess.Popen(
            [tor_binary, "-f", str(torrc), "--DataDirectory", str(data), "--ControlPort",
             f"127.0.0.1:{control_port}", "--CookieAuthentication", "1",
             "--CookieAuthFile", str(cookie), "--SocksPort", "0",
             "--DisableNetwork", "1", "--RunAsDaemon", "0"],
            stdout=log, stderr=log, env=environment)
        processes.append(process)

        def ready():
            if process.poll() is not None:
                raise AssertionError("Tor exited before ControlPort was ready")
            if not cookie.exists():
                return False
            try:
                with socket.create_connection(("127.0.0.1", control_port),
                                              timeout=0.2):
                    return True
            except OSError:
                return False

        wait_until(ready, "Tor ControlPort")
        return process

    def start_node():
        log = open(root / "node.log", "a+")
        logs.append(log)
        process = subprocess.Popen(
            [node_binary, "run", str(node_dir), "--log-level", "2",
             "--auto-onion", str(control_port), str(cookie), str(virtual_port)],
            stdout=log, stderr=log, env=environment)
        processes.append(process)

        def ready():
            if process.poll() is not None:
                raise AssertionError("node exited before onion service was ready")
            try:
                return fields(ctl(node_dir, "status")).get("onion", "").endswith(".onion")
            except (AssertionError, OSError):
                return False

        wait_until(ready, "node onion service")
        return process

    try:
        tor = start_tor()
        # A readable but incorrect cookie must fail server authentication.
        wrong_cookie = root / "wrong-cookie"
        wrong_cookie.write_bytes(os.urandom(32))
        wrong_cookie.chmod(0o600)
        rejected = subprocess.run(
            [node_binary, "run", str(root / "rejected"), "--auto-onion",
             str(control_port), str(wrong_cookie), str(virtual_port)],
            capture_output=True, text=True, timeout=8, env=environment)
        assert rejected.returncode != 0
        assert not (root / "rejected" / "onion.key").exists()

        node = start_node()
        first = fields(ctl(node_dir, "status"))
        assert len(first["onion"]) == 62
        assert first["onion_port"] == str(virtual_port)
        assert int(first["p2p_port"]) > 0
        key = node_dir / "onion.key"
        assert key.is_file() and key.stat().st_mode & 0o777 == 0o600

        assert ctl(node_dir, "stop") == "OK stopping"
        assert node.wait(timeout=10) == 0
        node = start_node()
        assert fields(ctl(node_dir, "status"))["onion"] == first["onion"]

        # A Tor restart closes the connection-tied service. The node should
        # register the same key again without changing its public address.
        tor.terminate()
        assert tor.wait(timeout=10) == 0
        wait_until(lambda: fields(ctl(node_dir, "status"))["onion"] == "offline",
                   "offline status", timeout=12)
        tor = start_tor()
        wait_until(lambda: fields(ctl(node_dir, "status"))["onion"] == first["onion"],
                   "onion restoration", timeout=15)
        assert ctl(node_dir, "stop") == "OK stopping"
        assert node.wait(timeout=10) == 0
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        for log in logs:
            log.close()

print("tor_onion_integration: OK")
