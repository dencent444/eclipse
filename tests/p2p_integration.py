"""Two processes independently validate forks, blocks and relayed transfers."""

import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

node_binary = str(pathlib.Path(sys.argv[1]))
fixture_binary = str(pathlib.Path(sys.argv[2]))
environment = dict(os.environ)
environment["ASAN_OPTIONS"] = "detect_leaks=0"


def call(*arguments, good=True):
    result = subprocess.run(arguments, text=True, capture_output=True,
                            env=environment, timeout=30)
    if good != (result.returncode == 0):
        raise AssertionError((arguments[:3], result.returncode,
                              result.stdout[-200:], result.stderr[-200:]))
    return (result.stdout if good else result.stderr).strip()


def fields(answer):
    assert answer.startswith("OK "), answer
    return dict(item.split("=", 1) for item in answer[3:].split()
                if "=" in item)


def wait_until(predicate, description, seconds=15):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if predicate():
            return
        time.sleep(0.1)
    raise AssertionError("timed out waiting for " + description)


with tempfile.TemporaryDirectory(prefix="eclipse-p2p-") as root:
    a_dir = str(pathlib.Path(root) / "a")
    b_dir = str(pathlib.Path(root) / "b")
    logs = []
    processes = []

    def start(directory, *options):
        log = open(str(pathlib.Path(root) / (pathlib.Path(directory).name + ".log")),
                   "a+")
        logs.append(log)
        process = subprocess.Popen([node_binary, "run", directory, "--log-level", "2",
                                    *options], stdout=log, stderr=log, env=environment)
        processes.append(process)
        def ready():
            if process.poll() is not None:
                raise AssertionError("node exited during startup")
            try:
                fields(ctl(directory, "status"))
                return True
            except AssertionError:
                return False
        wait_until(ready, "node startup")
        return process

    def ctl(directory, *arguments, good=True):
        return call(node_binary, "ctl", directory, *arguments, good=good)

    public_a = call(fixture_binary, "public")
    public_b = call(fixture_binary, "public2")
    try:
        # Two offline miners build different height-one branches. The later
        # network session must converge using deterministic fork choice.
        a = start(a_dir, "--p2p-listen", "127.0.0.1", "0")
        a_port = int(fields(ctl(a_dir, "status"))["p2p_port"])
        assert a_port > 0
        a_one = fields(ctl(a_dir, "mine", public_a))
        # A wrong network ID must be rejected before any block exchange.
        with socket.create_connection(("127.0.0.1", a_port), timeout=3) as rogue:
            rogue.settimeout(3)
            hello = (1).to_bytes(4, "big") + (0).to_bytes(4, "big") + bytes(88)
            rogue.sendall(b"EPN1\x01" + len(hello).to_bytes(4, "big") + hello)
            try:
                assert rogue.recv(1) == b""
            except ConnectionResetError:
                pass
        assert fields(ctl(a_dir, "status"))["tip"] == a_one["tip"]
        b = start(b_dir)
        b_one = fields(ctl(b_dir, "mine", public_b))
        assert a_one["tip"] != b_one["tip"]
        assert ctl(b_dir, "stop") == "OK stopping"
        assert b.wait(timeout=10) == 0
        b = start(b_dir, "--p2p-listen", "127.0.0.1", "0",
                  "--peer", "127.0.0.1", str(a_port))
        assert int(fields(ctl(b_dir, "status"))["p2p_port"]) > 0
        wait_until(lambda: fields(ctl(a_dir, "status"))["tip"] ==
                   fields(ctl(b_dir, "status"))["tip"], "fork convergence")

        # A newly mined reward reaches B, then B's signed pending spend
        # reaches A. The following block confirms it on both processes.
        second = fields(ctl(a_dir, "mine", public_a))
        assert second["height"] == "2"
        wait_until(lambda: fields(ctl(b_dir, "status"))["tip"] == second["tip"],
                   "block relay")
        reward = second["reward_outpoint"].split(":")[0]
        transaction = call(fixture_binary, "spend", reward)
        submitted = fields(ctl(b_dir, "submit-tx", transaction))
        assert submitted["mempool"] == "1"
        wait_until(lambda: fields(ctl(a_dir, "status"))["mempool"] == "1",
                   "transaction relay")
        third = fields(ctl(a_dir, "mine", public_a))
        assert third["height"] == "3"
        wait_until(lambda: fields(ctl(b_dir, "status"))["tip"] == third["tip"],
                   "confirmed block relay")
        assert fields(ctl(a_dir, "status"))["mempool"] == "0"
        assert fields(ctl(b_dir, "status"))["mempool"] == "0"
        for directory in (a_dir, b_dir):
            assert fields(ctl(directory, "utxo", submitted["txid"], "0"))["amount"] == "4999999999"
        assert ctl(a_dir, "stop") == "OK stopping"
        assert ctl(b_dir, "stop") == "OK stopping"
        assert a.wait(timeout=10) == 0
        assert b.wait(timeout=10) == 0
    except Exception:
        for log in logs:
            log.flush()
            log.seek(0)
            print(log.read()[-4000:], file=sys.stderr)
        raise
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        for log in logs:
            log.close()

print("p2p_integration: OK")
