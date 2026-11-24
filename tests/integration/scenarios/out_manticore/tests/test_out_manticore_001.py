"""Regular delivery, and the bulk receiver and Fluent Bit producer of the out_manticore cases."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ssl
import threading
import time
import urllib.error
import urllib.request

from utils.test_service import FluentBitTestService


def wait_until(predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.05)
    raise AssertionError("Timed out waiting for " + description)


def read_service_log(service):
    with open(service.flb.log_file, "r", encoding="utf-8", errors="replace") as stream:
        return stream.read()


def wait_for_service_log(service, expected, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        output = read_service_log(service)
        if expected in output:
            return output
        time.sleep(0.1)
    raise AssertionError("Fluent Bit log did not contain {!r}\n{}".format(
        expected, read_service_log(service)))


def stop_managed_service(service):
    process = service.flb.process
    log_file = service.flb.log_file
    service.stop()
    with open(log_file, "r", encoding="utf-8", errors="replace") as stream:
        output = stream.read()
    return process.returncode, output


class BulkHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        request = (self.requestline, {key.lower(): value for key, value in self.headers.items()}, body)
        self.server.requests.append(request)
        try:
            status, answer = self.server.handler(self.server, request)
        except Exception as error:
            self.server.errors.append(repr(error))
            raise
        if not isinstance(answer, bytes):
            answer = json.dumps(answer).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)


class BulkServer(ThreadingHTTPServer):
    """Records every request as (request line, headers, body); handler(server, request) gives
    the (status, body) of the reply."""

    daemon_threads = True

    def __init__(self, handler, tls=None):
        super().__init__(("127.0.0.1", 0), BulkHandler)
        if tls:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*map(str, tls))
            self.socket = context.wrap_socket(self.socket, server_side=True)
        self.handler = handler
        self.requests = []
        self.errors = []
        self.connections = 0
        self.port = self.server_address[1]
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def process_request(self, request, client_address):
        self.connections += 1
        super().process_request(request, client_address)

    def close(self):
        self.shutdown()
        self.server_close()
        self.thread.join(5)
        assert not self.errors, self.errors


class Producer:
    """Fluent Bit tailing a JSON lines file into one manticore output, Shared unless the options
    say otherwise."""

    def __init__(self, root, port, *, options=None, grace=2, tls=None, filters=None):
        root.mkdir(exist_ok=True)
        self.source = root / "records.json"
        self.source.write_text("")
        parser = root / "parsers.conf"
        parser.write_text("[PARSER]\n    Name shared_json\n    Format json\n")
        lines = [
            "service:", "  flush: 0.1", "  grace: {}".format(grace), "  log_level: info",
            "  scheduler.base: 1", "  scheduler.cap: 1", "  http_server: on",
            "  http_port: ${FLUENT_BIT_HTTP_MONITORING_PORT}",
            "  parsers_file: " + str(parser), "pipeline:", "  inputs:",
            "    - name: tail", "      tag: shared", "      path: " + str(self.source),
            "      refresh_interval: 1", "      read_from_head: true", "      parser: shared_json",
        ]
        if filters:
            lines.append("  filters:")
            for target in filters:
                lines.append("    - name: " + target["name"])
                for key, value in target.items():
                    if key != "name":
                        lines.append("      {}: {}".format(key, value))
        lines.append("  outputs:")
        output = {
            "match": "'*'", "host": "127.0.0.1", "port": port,
            "table": "shared_logs", "workers": 1, "mode": "sHaReD",
            "net.io_timeout": "2s", "http_user": "shared", "http_passwd": "test",
        }
        if tls:
            output.update({"tls": "on", "tls.verify": "on", "tls.verify_hostname": "on",
                           "tls.vhost": "localhost", "tls.ca_file": str(tls[0])})
        output.update(options or {})
        lines.append("    - name: manticore")
        for key, value in output.items():
            lines.append("      {}: {}".format(key, value))
        self.config = root / "fluent-bit.yaml"
        self.config.write_text("\n".join(lines) + "\n")
        self.service = FluentBitTestService(str(self.config))

    def start(self):
        self.service.start()

    def write(self, records):
        with self.source.open("a") as stream:
            for record in records:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    def metric(self, field):
        url = "http://127.0.0.1:{}/api/v1/metrics".format(
            self.service.flb.http_monitoring_port)
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                metrics = json.load(response)
        except urllib.error.HTTPError as error:
            if error.code == 404:
                return 0
            raise
        return sum(output.get(field, 0)
                   for name, output in metrics.get("output", {}).items()
                   if name.startswith("manticore"))

    def count(self):
        return self.metric("proc_records")

    def failed_records(self, total):
        wait_until(lambda: self.metric("dropped_records") == total, "terminal dropped records")

    def acknowledged(self, total):
        wait_until(lambda: self.count() == total, "acknowledged records {}".format(total))

    def stop(self):
        return stop_managed_service(self.service)


# Records go as they are, ids included or not: the daemon takes or gives the document id. A
# retryable item status retries the same chunk; a permanent one inside HTTP 500 drops it.
def test_out_manticore_regular_wire_validation_and_retry(tmp_path):
    def handle(server, request):
        if b"retry-item" in request[2] and sum(b"retry-item" in sent[2] for sent in server.requests) == 1:
            return 200, {"items": [{"bulk": {"status": 503}}], "errors": True}
        if b"permanent-item" in request[2]:
            return 500, {"items": [{"insert": {"status": 409}}], "errors": True}
        return 200, {"items": [{"bulk": {"status": 201}}], "errors": False}

    written = [{"id": document_id, "message": "wire-test", "status": 200}
               for document_id in range(1, 21)]
    written += [
        {"id": 1, "message": "wire-duplicate", "status": 201},
        {"message": "missing ID", "status": 202},
        {"id": 0, "message": "zero ID", "status": 203},
        {"id": {"invalid": True}, "message": "object ID", "status": 204},
    ]
    server = BulkServer(handle)
    producer = Producer(tmp_path, server.port, options={"mode": "Regular", "table": "'wire logs'"})
    producer.start()
    try:
        producer.write(written)
        producer.acknowledged(len(written))
        lines = [json.loads(line) for request in server.requests for line in request[2].splitlines()]
        assert lines == [{"insert": {"table": "wire logs", "doc": record}} for record in written]
        line, headers, body = server.requests[0]
        assert line == "POST /bulk HTTP/1.1"
        assert "transfer-encoding" not in headers
        assert headers["connection"] == "keep-alive"
        assert headers["content-type"] == "application/x-ndjson"
        assert headers["content-length"] == str(len(body))

        sent = len(server.requests)
        producer.write([{"id": 43, "message": "retry-item"}])
        producer.acknowledged(len(written) + 1)
        retried = server.requests[sent:]
        assert len(retried) == 2 and retried[0][2] == retried[1][2]

        producer.write([{"id": 44, "message": "permanent-item"}])
        producer.failed_records(1)
        code, output = producer.stop()
        assert code == 0, output
        assert sum(b"permanent-item" in request[2] for request in server.requests) == 1
        assert "retryable item error" in output
        assert "returned HTTP 500" in output
        assert "shared bulk_import" not in output
    finally:
        producer.service.stop()
        server.close()
