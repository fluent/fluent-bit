#  Fluent Bit
#  ==========
#  Copyright (C) 2015-2026 The Fluent Bit Authors
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


logger = logging.getLogger(__name__)

data_storage = {
    "requests": [],
}

server_thread = None
server_instance = None


def reset_s3_server_state():
    data_storage["requests"] = []


class _S3RequestHandler(BaseHTTPRequestHandler):
    server_version = "FakeS3/1.0"
    protocol_version = "HTTP/1.1"

    def _record_request(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        data_storage["requests"].append(
            {
                "method": self.command,
                "path": self.path,
                "headers": dict(self.headers),
                "body": body,
            }
        )

    def do_PUT(self):
        self._record_request()
        self.send_response(200)
        self.send_header("ETag", '"fake-s3-etag"')
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        self._record_request()
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "18")
            self.end_headers()
            self.wfile.write(b'{"status":"pong"}')
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format, *args):
        logger.debug("Fake S3 server: %s", format % args)


def s3_server_run(port):
    global server_thread
    global server_instance

    reset_s3_server_state()
    server_instance = ThreadingHTTPServer(("0.0.0.0", port), _S3RequestHandler)
    server_thread = threading.Thread(target=server_instance.serve_forever, daemon=True)
    server_thread.start()
    return server_thread


def s3_server_stop():
    global server_instance
    global server_thread

    if server_instance is not None:
        server_instance.shutdown()
        server_instance.server_close()
        server_instance = None

    if server_thread is not None:
        server_thread.join(timeout=5)
        server_thread = None
