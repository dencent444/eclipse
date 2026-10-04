"""A local fake SOCKS5 proxy checks onion domain routing without Tor installed."""

import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

node = str(pathlib.Path(sys.argv[1]))
fixture = str(pathlib.Path(sys.argv[2]))
environment = dict(os.environ)
environment["ASAN_OPTIONS"] = "detect_leaks=0"


def call(*arguments):
    completed = subprocess.run(arguments, env=environment, text=True,
                               capture_output=True, timeout=15)
    if completed.returncode != 0:
        raise AssertionError((arguments[:3], completed.stderr[-300:]))
    return completed.stdout.strip()


def field(reply, name):
    return dict(part.split("=", 1) for part in reply.split()[1:]
                if "=" in part)[name]


def recv_exact(connection, length):
    data = b""
    while len(data) < length:
        piece = connection.recv(length - len(data))
        if not piece:
            raise EOFError()
        data += piece
    return data


with tempfile.TemporaryDirectory(prefix="eclipse-socks-") as root:
    a_dir = str(pathlib.Path(root) / "a")
    b_dir = str(pathlib.Path(root) / "b")
    onion_host = "a" * 56 + ".onion"
    seen = []
    errors = []
    stop_proxy = threading.Event()
    proxy_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_listener.bind(("127.0.0.1", 0))
    proxy_listener.listen(4)
    proxy_listener.settimeout(0.2)
    proxy_port = proxy_listener.getsockname()[1]

    def proxy_loop(target_port):
        while not stop_proxy.is_set():
            try:
                client, _ = proxy_listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with client:
                    client.settimeout(5)
                    assert recv_exact(client, 3) == b"\x05\x01\x00"
                    client.sendall(b"\x05\x00")
                    request = recv_exact(client, 5)
                    assert request[:4] == b"\x05\x01\x00\x03"
                    host = recv_exact(client, request[4]).decode("ascii")
                    port = int.from_bytes(recv_exact(client, 2), "big")
                    seen.append((host, port))
                    with socket.create_connection(("127.0.0.1", target_port), 5) as upstream:
                        client.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01" +
                                       target_port.to_bytes(2, "big"))
                        client.settimeout(None)
                        while not stop_proxy.is_set():
                            readable, _, _ = select.select([client, upstream], [], [], 0.2)
                            for source in readable:
                                data = source.recv(65536)
                                if not data:
                                    raise EOFError()
                                (upstream if source is client else client).sendall(data)
            except (EOFError, ConnectionResetError, BrokenPipeError):
                pass
            except Exception as error:
                errors.append(error)

    logs = []
    processes = []

    def start(directory, *options):
        log = open(str(pathlib.Path(root) / (pathlib.Path(directory).name + ".log")),
                   "a+")
        logs.append(log)
        process = subprocess.Popen([node, "run", directory, "--log-level", "2",
                                    *options], env=environment, stdout=log, stderr=log)
        processes.append(process)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise AssertionError("node exited during startup")
            try:
                call(node, "ctl", directory, "status")
                return process
            except AssertionError:
                time.sleep(0.05)
        raise AssertionError("node did not start")

    thread = None
    try:
        a = start(a_dir, "--p2p-listen", "127.0.0.1", "0")
        port = int(field(call(node, "ctl", a_dir, "status"), "p2p_port"))
        public = call(fixture, "public")
        mined = field(call(node, "ctl", a_dir, "mine", public), "tip")
        # An onion target without SOCKS must fail before any direct DNS lookup.
        rejected = subprocess.run([node, "run", str(pathlib.Path(root) / "bad"),
                                   "--peer", onion_host + ".", "23456"],
                                  env=environment, text=True, capture_output=True,
                                  timeout=10)
        assert rejected.returncode != 0
        thread = threading.Thread(target=proxy_loop, args=(port,), daemon=True)
        thread.start()
        b = start(b_dir, "--peer", onion_host, "23456",
                  "--tor-socks", "127.0.0.1", str(proxy_port))
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if field(call(node, "ctl", b_dir, "status"), "tip") == mined:
                break
            time.sleep(0.1)
        else:
            raise AssertionError("onion SOCKS5 peer did not synchronize")
        assert seen and seen[0] == (onion_host, 23456), seen
        assert not errors, errors
        assert call(node, "ctl", b_dir, "stop") == "OK stopping"
        assert call(node, "ctl", a_dir, "stop") == "OK stopping"
        assert b.wait(timeout=10) == 0
        assert a.wait(timeout=10) == 0
    except Exception:
        for log in logs:
            log.flush()
            log.seek(0)
            print(log.read()[-3000:], file=sys.stderr)
        raise
    finally:
        stop_proxy.set()
        proxy_listener.close()
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        if thread is not None:
            thread.join(timeout=5)
        for log in logs:
            log.close()

print("p2p_socks: OK")
