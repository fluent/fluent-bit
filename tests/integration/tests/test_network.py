import os
import socket
import json
import subprocess
import sys

import pytest

from utils.network import find_available_port, wait_for_port_to_be_free


def test_port_allocations_are_distinct():
    ports = [find_available_port() for _ in range(100)]
    assert len(set(ports)) == len(ports)


def test_probe_rejects_a_live_listener():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        assert not wait_for_port_to_be_free(port, timeout=0.1, interval=0.01)
        assert find_available_port(port) != port


def test_available_port_excludes_active_reusable_client():
    with socket.socket() as server, socket.socket() as client:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        client.connect(server.getsockname())
        connection, _ = server.accept()
        try:
            client_port = client.getsockname()[1]
            assert find_available_port(client_port) != client_port
        finally:
            connection.close()


@pytest.mark.skipif(sys.platform != "linux", reason="Linux ephemeral-port allocation")
def test_linux_workers_allocate_distinct_non_ephemeral_ports():
    with open("/proc/sys/net/ipv4/ip_local_port_range", encoding="ascii") as source:
        low, high = (int(value) for value in source.read().split())
    command = [sys.executable, "-c", "import json; from utils.network import find_available_port; "
               "print(json.dumps([find_available_port() for _ in range(20)]))"]
    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.join(os.path.dirname(__file__), "../src"))
    workers = []
    ports = []
    try:
        for _ in range(8):
            workers.append(subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE, text=True))
        for worker in workers:
            output, errors = worker.communicate(timeout=20)
            assert worker.returncode == 0, errors
            ports.extend(json.loads(output))
    finally:
        for worker in workers:
            if worker.poll() is None:
                worker.kill()
            worker.communicate()
    assert len(ports) == len(set(ports))
    assert all(not low <= port <= high for port in ports)
