import contextlib
import http.server
import json
import os
import threading
import time

from utils.test_service import FluentBitTestService


class _KubeApiServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.list_requests = 0
        self.watch_requests = 0
        self.watch_paths = []


class _KubeApiHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if "watch=1" in self.path:
            with self.server.lock:
                self.server.watch_requests += 1
                self.server.watch_paths.append(self.path)

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            self.wfile.flush()
            self.server.stop_event.wait(timeout=30)
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        with self.server.lock:
            self.server.list_requests += 1
            resource_version = self.server.list_requests

        payload = json.dumps(
            {
                "kind": "EventList",
                "apiVersion": "v1",
                "metadata": {"resourceVersion": str(resource_version)},
                "items": [],
            }
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
        self.wfile.flush()

    def log_message(self, fmt, *args):
        return


@contextlib.contextmanager
def _run_kube_api_server():
    server = _KubeApiServer(("127.0.0.1", 0), _KubeApiHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        yield server
    finally:
        server.stop_event.set()
        server.shutdown()
        server.server_close()
        thread.join()


def _write_config(tmp_path, kube_api_port):
    token_file = tmp_path / "token"
    token_file.write_text("test-token", encoding="utf-8")
    config_file = tmp_path / "kubernetes_events_watch_timeout.conf"
    config_file.write_text(
        "\n".join(
            [
                "[SERVICE]",
                "    Flush 1",
                "    Grace 1",
                "    Log_Level info",
                "    HTTP_Server On",
                "    HTTP_Port ${FLUENT_BIT_HTTP_MONITORING_PORT}",
                "",
                "[INPUT]",
                "    Name kubernetes_events",
                f"    Kube_URL http://127.0.0.1:{kube_api_port}",
                f"    Kube_Token_File {token_file}",
                "    tls Off",
                "    Interval_Sec 2",
                "    Interval_NSec 0",
                "    Kube_Watch_Timeout 1s",
                "",
                "[OUTPUT]",
                "    Name null",
                "    Match *",
            ]
        ),
        encoding="utf-8",
    )
    return config_file


def test_kubernetes_events_reconnects_stalled_watch(tmp_path):
    with _run_kube_api_server() as kube_api_server:
        config_file = _write_config(tmp_path, kube_api_server.server_address[1])
        service = FluentBitTestService(os.fspath(config_file))
        service.start()

        try:
            service.wait_for_condition(
                lambda: kube_api_server.watch_requests
                if kube_api_server.watch_requests >= 2
                else None,
                timeout=10,
                interval=0.25,
                description="a reconnected Kubernetes event watch",
            )
            kube_api_server.stop_event.set()
            time.sleep(0.5)
        finally:
            service.stop()

        assert kube_api_server.list_requests >= 2
        assert kube_api_server.watch_requests >= 2
        assert all("timeoutSeconds=1" in path for path in kube_api_server.watch_paths)
