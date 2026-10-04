"""Generate canonical dev tx/block corpus entries from existing node APIs."""

import pathlib
import subprocess
import sys
import tempfile
import time

node = sys.argv[1]
fixture = sys.argv[2]
corpus = pathlib.Path(sys.argv[3])
corpus.mkdir(parents=True, exist_ok=True)


def call(*words):
    result = subprocess.run(words, capture_output=True, text=True, timeout=15)
    if result.returncode != 0:
        raise RuntimeError((words[:3], result.stderr[-300:]))
    return result.stdout.strip()


def field(answer, name):
    return dict(part.split("=", 1) for part in answer.split()
                if "=" in part)[name]


public = call(fixture, "public")
tx = call(fixture, "spend", "00" * 32)
(corpus / "signed-tx").write_bytes(b"\x00" + bytes.fromhex(tx))

with tempfile.TemporaryDirectory(prefix="eclipse-fuzz-seed-") as data:
    with subprocess.Popen([node, "run", data, "--log-level", "0"],
                          stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL) as process:
        try:
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("seed node exited before startup")
                try:
                    call(node, "ctl", data, "status")
                    break
                except RuntimeError:
                    time.sleep(0.05)
            else:
                raise RuntimeError("seed node did not start")
            mined = call(node, "ctl", data, "mine", public)
            block = call(node, "ctl", data, "get-block", field(mined, "tip"))
            if not block.startswith("OK "):
                raise RuntimeError("unexpected get-block response")
            (corpus / "mined-block").write_bytes(
                b"\x01" + bytes.fromhex(block[3:]))
            call(node, "ctl", data, "stop")
            if process.wait(timeout=10) != 0:
                raise RuntimeError("seed node failed to stop")
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)

print("fuzz_seed: wrote signed transaction and mined block")
