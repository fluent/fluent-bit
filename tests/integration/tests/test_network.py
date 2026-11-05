"""Port probes must reflect whether a new listener can bind exclusively."""
import socket

from src.utils.network import find_available_port


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
