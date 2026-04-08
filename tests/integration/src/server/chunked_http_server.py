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

from __future__ import annotations

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


logger = logging.getLogger(__name__)

chunked_response_storage = {"payloads": [], "requests": []}
chunked_response_config = {
    "status_code": 200,
    "reason": "OK",
    "headers": [
        ("Transfer-Encoding", "chunked"),
        ("Connection", "close"),
    ],
    "fragments": [
        "2\r\nOK\r\n",
        "0\r\n\r\n",
    ],
    "delay_seconds": 0.0,
    "fragment_delay_seconds": 0.01,
    "hang_before_headers": False,
    "hang_after_fragment_index": None,
}

server_thread = None
server_instance = None
shutdown_event = threading.Event()


class ChunkedThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def _sleep_interruptible(seconds):
    if seconds <= 0:
        return

    deadline = time.time() + seconds

    while time.time() < deadline:
        if shutdown_event.wait(timeout=min(0.1, deadline - time.time())):
            break


def _wait_for_shutdown():
    shutdown_event.wait(timeout=30)


def reset_chunked_http_server_state():
    shutdown_event.clear()
    chunked_response_storage["payloads"] = []
    chunked_response_storage["requests"] = []
    chunked_response_config.update(
        {
            "status_code": 200,
            "reason": "OK",
            "headers": [
                ("Transfer-Encoding", "chunked"),
                ("Connection", "close"),
            ],
            "fragments": [
                "2\r\nOK\r\n",
                "0\r\n\r\n",
            ],
            "delay_seconds": 0.0,
            "fragment_delay_seconds": 0.01,
            "hang_before_headers": False,
            "hang_after_fragment_index": None,
        }
    )


def configure_chunked_http_response(*, status_code=None, reason=None,
                                    headers=None, fragments=None,
                                    delay_seconds=None,
                                    fragment_delay_seconds=None,
                                    hang_before_headers=None,
                                    hang_after_fragment_index=None):
    if status_code is not None:
        chunked_response_config["status_code"] = status_code
    if reason is not None:
        chunked_response_config["reason"] = reason
    if headers is not None:
        chunked_response_config["headers"] = list(headers)
    if fragments is not None:
        chunked_response_config["fragments"] = list(fragments)
    if delay_seconds is not None:
        chunked_response_config["delay_seconds"] = delay_seconds
    if fragment_delay_seconds is not None:
        chunked_response_config["fragment_delay_seconds"] = fragment_delay_seconds
    if hang_before_headers is not None:
        chunked_response_config["hang_before_headers"] = hang_before_headers
    if hang_after_fragment_index is not None:
        chunked_response_config["hang_after_fragment_index"] = hang_after_fragment_index


def _decode_json_payload(decoded_payload):
    if not decoded_payload:
        return None

    try:
        return json.loads(decoded_payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _record_request(handler, payload):
    raw_data = payload.decode("utf-8", errors="replace")
    chunked_response_storage["payloads"].append(_decode_json_payload(payload))
    chunked_response_storage["requests"].append(
        {
            "path": handler.path,
            "method": handler.command,
            "headers": dict(handler.headers),
            "raw_data": raw_data,
            "decoded_data": raw_data,
            "json": _decode_json_payload(payload),
        }
    )


class ChunkedHTTPHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        logger.debug("chunked_http_server: " + fmt, *args)

    def do_GET(self):
        if self.path == "/ping":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len('{"status":"pong"}')))
            self.end_headers()
            self.wfile.write(b'{"status":"pong"}')
            self.wfile.flush()
            return

        if self.path == "/shutdown":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()
            self.wfile.flush()
            threading.Thread(target=self.server.shutdown, daemon=True).start()
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(content_length) if content_length > 0 else b""

        _record_request(self, payload)

        if chunked_response_config["delay_seconds"] > 0:
            _sleep_interruptible(chunked_response_config["delay_seconds"])

        if chunked_response_config["hang_before_headers"]:
            _wait_for_shutdown()
            self.close_connection = True
            return

        status_code = chunked_response_config["status_code"]
        reason = chunked_response_config["reason"]

        self.connection.sendall(
            f"HTTP/1.1 {status_code} {reason}\r\n".encode("utf-8")
        )

        for key, value in chunked_response_config["headers"]:
            self.connection.sendall(f"{key}: {value}\r\n".encode("utf-8"))

        self.connection.sendall(b"\r\n")

        for fragment in chunked_response_config["fragments"]:
            if isinstance(fragment, str):
                fragment = fragment.encode("utf-8")

            self.connection.sendall(fragment)
            if chunked_response_config["hang_after_fragment_index"] == 0:
                _wait_for_shutdown()
                self.close_connection = True
                return

            if chunked_response_config["hang_after_fragment_index"] is not None:
                chunked_response_config["hang_after_fragment_index"] -= 1

            _sleep_interruptible(chunked_response_config["fragment_delay_seconds"])

        self.close_connection = True


def _serve(port):
    global server_instance

    server_instance = ChunkedThreadingHTTPServer(("127.0.0.1", port),
                                                 ChunkedHTTPHandler)
    server_instance.serve_forever()


def chunked_http_server_run(port=60000, *, reset_state=True):
    global server_thread

    if reset_state:
        reset_chunked_http_server_state()

    logger.info("Starting chunked HTTP server on port %s", port)
    server_thread = threading.Thread(target=_serve, args=(port,), daemon=True)
    server_thread.start()
    return server_thread


def shutdown_chunked_http_server():
    global server_instance

    shutdown_event.set()

    if server_instance is not None:
        server_instance.shutdown()
        server_instance.server_close()
        server_instance = None
