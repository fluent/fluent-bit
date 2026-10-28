import os
import socket

import pytest

from utils.network import find_available_port, wait_for_port_to_be_free


@pytest.mark.skipif(os.name != "nt", reason="Windows port allocation regression")
def test_windows_port_allocations_are_distinct():
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
