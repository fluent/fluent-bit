import os
import socket
import threading
import time

from utils.data_utils import read_file
from utils.fluent_bit_manager import FluentBitManager
from utils.network import wait_for_port_to_be_free


BOGUS_HELO_UINT64 = 0x4141414141414141


class InvalidHeloServer:
    def __init__(self):
        self.port = None
        self.connection_count = 0
        self._lock = threading.Lock()
        self._server = None
        self._stop_event = threading.Event()
        self._thread = None

    def start(self):
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.bind(("127.0.0.1", 0))
        self._server.listen(5)
        self._server.settimeout(0.5)
        self.port = self._server.getsockname()[1]
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()

        if self.port is not None:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    pass
            except OSError:
                pass

        if self._thread:
            self._thread.join(timeout=2)

        if self._server:
            self._server.close()

        if self.port is not None:
            wait_for_port_to_be_free(
                self.port,
                timeout=10 if os.environ.get("VALGRIND") else 5,
            )

    def wait_for_connections(self, minimum_count, timeout):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                if self.connection_count >= minimum_count:
                    return True
            time.sleep(0.1)
        return False

    def _run(self):
        helo = b"\xcf" + BOGUS_HELO_UINT64.to_bytes(8, "big")

        while not self._stop_event.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            with self._lock:
                self.connection_count += 1

            with conn:
                try:
                    conn.sendall(helo)
                    time.sleep(0.2)
                except OSError:
                    pass


def _wait_for_log_contains(log_file, text, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(log_file) and text in read_file(log_file):
            return True
        time.sleep(0.2)
    return False


def test_out_forward_secure_forward_rejects_non_array_helo():
    config_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "../config"))
    config_file = os.path.join(config_dir, "out_forward_secure_invalid_helo.yaml")
    server = InvalidHeloServer()
    previous_port = os.environ.get("OUT_FORWARD_INVALID_HELO_PORT")
    timeout = 30 if os.environ.get("VALGRIND") else 10
    fluent_bit = FluentBitManager(config_file)

    server.start()
    os.environ["OUT_FORWARD_INVALID_HELO_PORT"] = str(server.port)

    try:
        fluent_bit.start()

        assert server.wait_for_connections(1, timeout=timeout)
        assert _wait_for_log_contains(fluent_bit.log_file, "Invalid HELO message", timeout)
        assert fluent_bit.process.poll() is None
    finally:
        fluent_bit.stop()
        server.stop()

        if previous_port is None:
            os.environ.pop("OUT_FORWARD_INVALID_HELO_PORT", None)
        else:
            os.environ["OUT_FORWARD_INVALID_HELO_PORT"] = previous_port
