"""A partial bulk retry in upstream mode goes back to the node that built it."""
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
import time

from utils.fluent_bit_manager import FluentBitManager


class Cluster:
    """Two fake Elasticsearch nodes sharing one request log."""

    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.servers = [self._server(name) for name in ("node_a", "node_b")]
        for server in self.servers:
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def _server(self, name):
        cluster = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                lines = [json.loads(line) for line in body.splitlines() if line.strip()]
                actions = lines[0::2]
                with cluster.lock:
                    first = not cluster.requests
                    cluster.requests.append((name, actions))
                # Answer with the same operation as each action line.
                items = [{next(iter(action)): {"status": 201}} for action in actions]
                if first and len(items) > 1:
                    # Fail the last document of the first bulk request only.
                    items[-1] = {next(iter(actions[-1])): {"status": 503, "error": {
                        "type": "unavailable_shards_exception", "reason": "test"}}}
                payload = json.dumps({"took": 1, "errors": first, "items": items}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args):
                pass

        return ThreadingHTTPServer(("127.0.0.1", 0), Handler)

    def port(self, index):
        return self.servers[index].server_address[1]

    def snapshot(self):
        with self.lock:
            return list(self.requests)

    def close(self):
        for server in self.servers:
            server.shutdown()
            server.server_close()


def test_partial_retry_goes_back_to_the_same_node(tmp_path):
    cluster = Cluster()
    upstream = tmp_path / "upstream.conf"
    upstream.write_text(
        "[UPSTREAM]\n"
        "    name es_cluster\n\n"
        "[NODE]\n"
        "    name node_a\n"
        "    host 127.0.0.1\n"
        f"    port {cluster.port(0)}\n"
        "    index index_a\n\n"
        "[NODE]\n"
        "    name node_b\n"
        "    host 127.0.0.1\n"
        f"    port {cluster.port(1)}\n"
        "    index index_b\n"
    )
    config = tmp_path / "fluent-bit.yaml"
    config.write_text(json.dumps({
        "service": {
            "flush": 1,
            "grace": 1,
            "scheduler.base": 1,
            "scheduler.cap": 2,
            "http_server": "on",
            "http_listen": "127.0.0.1",
            "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}",
        },
        "pipeline": {
            "inputs": [{"name": "dummy", "samples": 1, "copies": 2,
                        "dummy": '{"message": "hello"}'}],
            "outputs": [{"name": "es", "match": "*", "upstream": str(upstream),
                         "suppress_type_name": "on", "retry_limit": 5}],
        },
    }))

    manager = FluentBitManager(str(config))
    try:
        manager.start()
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline and len(cluster.snapshot()) < 2:
            time.sleep(0.1)
    finally:
        manager.stop()
        cluster.close()

    requests = cluster.snapshot()
    assert len(requests) >= 2, f"expected the first request and a retry, got {requests}"

    first_node, first_actions = requests[0]
    retry_node, retry_actions = requests[1]
    assert len(first_actions) == 2
    # Only the failed document is retried, to the node that answered the
    # first request, with that node's index.
    assert retry_node == first_node
    assert len(retry_actions) == 1
    expected_index = "index_a" if first_node == "node_a" else "index_b"
    operation = next(iter(retry_actions[0]))
    assert retry_actions[0][operation]["_index"] == expected_index
