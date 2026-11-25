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
import json
from datetime import datetime, timedelta, timezone
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


logger = logging.getLogger(__name__)

data_storage = {
    "requests": [],
}

server_thread = None
server_instance = None


class TaggedUploadBarrier:
    """Hold the first PUT for each tag until all expected tags are in flight."""

    def __init__(self, tags, timeout=15):
        self.tags = set(tags)
        self.seen = set()
        self.lock = threading.Lock()
        self.barrier = threading.Barrier(len(self.tags), timeout=timeout)

    def wait(self, tag):
        with self.lock:
            if tag not in self.tags or tag in self.seen:
                return None
            self.seen.add(tag)
        try:
            self.barrier.wait()
            return True
        except threading.BrokenBarrierError:
            return False


def reset_s3_server_state():
    data_storage["requests"] = []
    data_storage["put_status"] = 200
    data_storage["put_delay"] = 0
    data_storage["upload_barrier"] = None
    data_storage["credential_mode"] = None
    data_storage["credential_requests"] = 0
    data_storage["auth_failures"] = set()
    data_storage["state_lock"] = threading.Lock()
    data_storage["response_override"] = None


class _S3RequestHandler(BaseHTTPRequestHandler):
    server_version = "FakeS3/1.0"
    protocol_version = "HTTP/1.1"

    def _record_request(self):
        started = time.monotonic()
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b""
        request = {
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body,
            "started": started,
        }
        data_storage["requests"].append(request)
        return request

    def _finish_request(self, request, status, body, headers=()):
        override = data_storage["response_override"]
        if override is not None:
            response = override(request)
            if response is not None:
                status, body, headers = response
        request["finished"] = time.monotonic()
        self.send_response(status)
        for name, value in headers:
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)
        request["status"] = status

    def do_PUT(self):
        request = self._record_request()
        status = data_storage["put_status"]
        tag = urlsplit(self.path).path.split("/")[2]
        with data_storage["state_lock"]:
            if data_storage["credential_mode"] == "refresh" and tag not in data_storage["auth_failures"]:
                data_storage["auth_failures"].add(tag)
                status = 403
        barrier = data_storage["upload_barrier"]
        if barrier is not None and status == 200:
            request["barrier_passed"] = barrier.wait(tag)
        time.sleep(data_storage["put_delay"])
        body = b""
        if status == 403:
            body = b"<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>"
        self._finish_request(request, status, body, [("ETag", '"fake-s3-etag"')])

    def do_DELETE(self):
        self._finish_request(self._record_request(), 204, b"")

    def do_POST(self):
        request = self._record_request()
        time.sleep(data_storage["put_delay"])
        body = b""
        if "uploads" in parse_qs(urlsplit(self.path).query, keep_blank_values=True):
            request["upload_id"] = uuid.uuid4().hex
            body = ("<InitiateMultipartUploadResult><UploadId>"
                    f"{request['upload_id']}"
                    "</UploadId></InitiateMultipartUploadResult>").encode()
        self._finish_request(request, 200, body)

    def do_GET(self):
        if self.path == "/credentials":
            with data_storage["state_lock"]:
                data_storage["credential_requests"] += 1
                generation = data_storage["credential_requests"]
            # A 30-second lifetime falls inside the provider's refresh window.
            lifetime = 30 if data_storage["credential_mode"] == "expiring" else 3600
            expiration = datetime.now(timezone.utc) + timedelta(seconds=lifetime)
            body = json.dumps({
                "AccessKeyId": f"test-access-{generation}",
                "SecretAccessKey": f"test-secret-{generation}",
                "Token": f"test-token-{generation}",
                "Expiration": expiration.strftime("%Y-%m-%dT%H:%M:%SZ"),
            }).encode()
            time.sleep(0.1)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

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
