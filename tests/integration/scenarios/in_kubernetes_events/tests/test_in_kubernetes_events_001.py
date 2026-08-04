import contextlib
import http.server
import json
import os
import threading
import time

from utils.data_utils import read_file
from utils.test_service import FluentBitTestService


EVENT_UID = "watch-event-uid"
RECOVERED_EVENT_UID = "post-recovery-event-uid"


def _event(resource_version, uid=None):
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event = {
        "metadata": {
            "creationTimestamp": timestamp,
            "resourceVersion": str(resource_version),
        }
    }
    if uid is not None:
        event["metadata"]["uid"] = uid
    return event


class _KubeApiServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.list_requests = 0
        self.watch_requests = 0
        self.watch_paths = []
        self.event = _event(2, EVENT_UID)
        self.recovered_event = _event(3, RECOVERED_EVENT_UID)
        self.uidless_event = _event(4)


class _KubeApiHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if "watch=1" in self.path:
            with self.server.lock:
                self.server.watch_requests += 1
                self.server.watch_paths.append(self.path)
                watch_request = self.server.watch_requests

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if watch_request <= 2:
                event = self.server.event
                type_key = "type"
                if watch_request == 1:
                    type_key = "typeExtra"
                if watch_request == 2:
                    event = self.server.recovered_event
                payload = (
                    json.dumps({type_key: "ADDED", "object": event}) + "\n"
                ).encode("utf-8")
                self.wfile.write(f"{len(payload):x}\r\n".encode("ascii"))
                self.wfile.write(payload)
                self.wfile.write(b"\r\n")
            self.wfile.flush()
            if watch_request == 2:
                time.sleep(0.5)
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
                return
            self.server.stop_event.wait(timeout=30)
            try:
                self.wfile.write(b"0\r\n\r\n")
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            return

        with self.server.lock:
            self.server.list_requests += 1
            list_request = self.server.list_requests

        payload = json.dumps(
            {
                "kind": "EventList",
                "apiVersion": "v1",
                "metadata": {"resourceVersion": str(min(list_request, 2))},
                "items": (
                    [self.server.event, self.server.uidless_event]
                    if list_request > 1
                    else []
                ),
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
    database_file = tmp_path / "kubernetes-events.db"
    config_file = tmp_path / "kubernetes_events_watch_timeout.conf"
    config_file.write_text(
        "\n".join(
            [
                "[SERVICE]",
                "    Flush 1",
                "    Grace 1",
                "    Log_Level debug",
                "    HTTP_Server On",
                "    HTTP_Port ${FLUENT_BIT_HTTP_MONITORING_PORT}",
                "",
                "[INPUT]",
                "    Name kubernetes_events",
                f"    Kube_URL http://127.0.0.1:{kube_api_port}",
                f"    Kube_Token_File {token_file}",
                f"    Db {database_file}",
                "    tls Off",
                "    Interval_Sec 5",
                "    Interval_NSec 0",
                "    Kube_Watch_Timeout 1s",
                "",
                "[OUTPUT]",
                "    Name stdout",
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
        log_file = service.flb.log_file

        try:
            service.wait_for_condition(
                lambda: RECOVERED_EVENT_UID
                if kube_api_server.watch_requests >= 2
                and RECOVERED_EVENT_UID in read_file(log_file)
                and read_file(log_file).count("kubernetes stream disconnected") >= 2
                else None,
                timeout=20,
                interval=0.25,
                description="an event from the reconnected Kubernetes watch",
            )
        finally:
            service.stop()

        with open(log_file, encoding="utf-8") as log:
            log_text = log.read()
        assert kube_api_server.list_requests >= 2
        assert kube_api_server.watch_requests >= 2
        assert all("timeoutSeconds=1" in path for path in kube_api_server.watch_paths)
        assert log_text.count(f'"uid"=>"{EVENT_UID}"') == 1
        assert log_text.count(f'"uid"=>"{RECOVERED_EVENT_UID}"') == 1
        assert "Streamed Event 'type' not found" in log_text
        assert "Cannot get uid for item in response" in log_text
        assert "unable to find uid in metadata to save event" in log_text
        assert "unable to find metadata to save event" not in log_text
        assert f"inserted k8s event: uid={EVENT_UID}" in log_text
        assert f"inserted k8s event: uid={RECOVERED_EVENT_UID}" in log_text
