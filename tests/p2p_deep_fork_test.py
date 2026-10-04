"""A fork longer than one transfer batch must advance across sessions."""

import os
import pathlib
import subprocess
import sys
import tempfile
import time

node = str(pathlib.Path(sys.argv[1]))
fixture = str(pathlib.Path(sys.argv[2]))
environment = dict(os.environ)
environment["ASAN_OPTIONS"] = "detect_leaks=0"


def call(*arguments):
    result = subprocess.run(arguments, capture_output=True, text=True,
                            env=environment, timeout=30)
    if result.returncode != 0:
        raise AssertionError((arguments[:3], result.stderr[-300:]))
    return result.stdout.strip()


def values(answer):
    return dict(part.split("=", 1) for part in answer.split()[1:]
                if "=" in part)


with tempfile.TemporaryDirectory(prefix="eclipse-deep-fork-") as root:
    directories = [str(pathlib.Path(root) / name) for name in ("a", "b")]
    logs = [open(str(pathlib.Path(root) / (name + ".log")), "a+")
            for name in ("a", "b")]
    processes = []

    def start(which, *options):
        process = subprocess.Popen([node, "run", directories[which],
                                    "--log-level", "1", *options],
                                   env=environment, stdout=logs[which],
                                   stderr=logs[which])
        processes.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("node exited during startup")
            try:
                call(node, "ctl", directories[which], "status")
                return process
            except AssertionError:
                time.sleep(0.05)
        raise AssertionError("node did not start")

    try:
        public = [call(fixture, "public"), call(fixture, "public2")]
        active = [start(0), start(1)]
        for _ in range(130):
            for which in (0, 1):
                call(node, "ctl", directories[which], "mine", public[which])
        original = [values(call(node, "ctl", directory, "status"))["tip"]
                    for directory in directories]
        assert original[0] != original[1]
        for which in (0, 1):
            assert call(node, "ctl", directories[which], "stop") == "OK stopping"
            assert active[which].wait(timeout=10) == 0

        active[0] = start(0, "--p2p-listen", "127.0.0.1", "0")
        port = values(call(node, "ctl", directories[0], "status"))["p2p_port"]
        active[1] = start(1, "--peer", "127.0.0.1", port)
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            latest = [values(call(node, "ctl", directory, "status"))
                      for directory in directories]
            if latest[0]["tip"] == latest[1]["tip"]:
                assert latest[0]["height"] == latest[1]["height"] == "130"
                assert latest[0]["tip"] == min(original)
                break
            time.sleep(0.15)
        else:
            raise AssertionError("deep fork did not converge across batches")
        for which in (0, 1):
            assert call(node, "ctl", directories[which], "stop") == "OK stopping"
            assert active[which].wait(timeout=10) == 0
    except Exception:
        for log in logs:
            log.flush()
            log.seek(0)
            print(log.read()[-3000:], file=sys.stderr)
        raise
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        for log in logs:
            log.close()

print("p2p_deep_fork: OK")
