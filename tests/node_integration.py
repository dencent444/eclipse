"""Exercise a real node process, its local socket, journal lock and restart."""

import os
import pathlib
import subprocess
import sys
import tempfile
import time

node_binary = pathlib.Path(sys.argv[1])
fixture_binary = pathlib.Path(sys.argv[2])
environment = dict(os.environ)
environment["ASAN_OPTIONS"] = "detect_leaks=0"


def call(*arguments, good=True):
    result = subprocess.run(arguments, text=True, capture_output=True,
                            env=environment, timeout=30)
    if good != (result.returncode == 0):
        raise AssertionError((arguments[:3], result.returncode,
                              result.stdout[-200:], result.stderr[-200:]))
    return (result.stdout if good else result.stderr).strip()


def fields(response):
    assert response.startswith("OK "), response
    return dict(item.split("=", 1) for item in response[3:].split()
                if "=" in item)


with tempfile.TemporaryDirectory(prefix="eclipse-node-") as directory:
    log_path = pathlib.Path(directory) / "node.log"

    public = call(str(fixture_binary), "public")

    def control(*arguments, good=True):
        return call(str(node_binary), "ctl", directory, *arguments, good=good)

    def launch(log):
        return subprocess.Popen([str(node_binary), "run", directory,
                                 "--log-level", "2"], stdout=log,
                                stderr=log, env=environment)

    def ready(process):
        for _ in range(100):
            if process.poll() is not None:
                raise AssertionError("node exited during startup")
            try:
                return fields(control("status"))
            except AssertionError:
                time.sleep(0.05)
        raise AssertionError("node socket was not ready")

    with log_path.open("w+") as log:
        process = launch(log)
        try:
            start = ready(process)
            assert start["height"] == "0" and start["mempool"] == "0"
            assert control("mempool") == "OK count=0"
            assert control("submit-tx", "00", good=False) == "ERR rejected_transaction"
            assert control("submit-block", "00", good=False) == "ERR rejected_block"

            # The journal lock prevents a second writer from becoming a node.
            rival = subprocess.run([str(node_binary), "run", directory],
                                   env=environment, capture_output=True,
                                   timeout=10)
            assert rival.returncode != 0

            mined = fields(control("mine", public))
            assert mined["height"] == "1"
            reward_id = mined["reward_outpoint"].split(":")[0]
            output = fields(control("utxo", reward_id, "0"))
            assert output["found"] == "1" and output["amount"] == "5000000000"
            assert control("utxo", reward_id, "1") == "OK found=0"
            wire = control("get-block", mined["tip"])
            assert wire.startswith("OK ") and len(wire) > 200
            assert control("submit-block", wire[3:], good=False) == "ERR rejected_block"
            transaction = call(str(fixture_binary), "spend", reward_id)
            admitted = fields(control("submit-tx", transaction))
            assert admitted["mempool"] == "1"
            assert control("submit-tx", transaction, good=False) == "ERR rejected_transaction"
            assert fields(control("status"))["mempool"] == "1"
            second = fields(control("mine", public))
            assert second["height"] == "2"
            assert fields(control("status"))["mempool"] == "0"
            assert control("utxo", reward_id, "0") == "OK found=0"
            assert fields(control("utxo", admitted["txid"], "0"))["amount"] == "4999999999"
            assert control("stop") == "OK stopping"
            assert process.wait(timeout=10) == 0

            # Opening a fresh process must replay the same block and UTXO.
            process = launch(log)
            reopened = ready(process)
            assert reopened["height"] == "2" and reopened["tip"] == second["tip"]
            assert reopened["mempool"] == "0"
            assert control("utxo", reward_id, "0") == "OK found=0"
            assert fields(control("utxo", admitted["txid"], "0"))["amount"] == "4999999999"
            assert control("get-block", mined["tip"]) == wire
            process.kill()
            assert process.wait(timeout=10) != 0

            # A killed process leaves a stale socket; journal replay and the
            # journal lock must still let exactly one replacement start.
            process = launch(log)
            after_crash = ready(process)
            assert after_crash["height"] == "2"
            assert after_crash["tip"] == second["tip"]
            assert control("stop") == "OK stopping"
            assert process.wait(timeout=10) == 0
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

print("node_integration: OK")
