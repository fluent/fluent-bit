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

"""In-memory fake of the parts of Google Cloud Storage used by in_gcs.

One server instance plays two roles, so that a single port can be given both
as the plugin ``endpoint`` and as its ``metadata_server``:

* GCE metadata server: ``GET /computeMetadata/v1/instance/service-accounts/default/token``
* Cloud Storage JSON API:
    * ``GET /storage/v1/b/<bucket>/o``            object listing
    * ``GET /storage/v1/b/<bucket>/o/<name>?alt=media``  object download

Everything is configured by the test through the public methods of
``FakeGcsServer`` and every request is recorded in ``requests``.
"""

import json
import logging
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit


logger = logging.getLogger(__name__)

TOKEN_PATH = "/computeMetadata/v1/instance/service-accounts/default/token"


class _GcsObject:
    def __init__(self, data, generation, content_type):
        self.data = data
        self.generation = generation
        self.content_type = content_type
        self.status = None           # fixed status returned instead of the content
        self.fail_times = 0          # remaining failures before the object is served
        self.fail_status = 500


class FakeGcsServer:
    def __init__(self, bucket="test-bucket"):
        self.bucket = bucket
        self.lock = threading.Lock()
        self.objects = {}
        self.requests = []
        self.tokens = ["test-token"]
        self.accepted_tokens = None
        self.token_status = 200
        self.token_hits = 0
        self.list_status = None
        self.list_fail_times = 0
        self._generation_counter = 1700000000000000
        self._httpd = None
        self._thread = None
        self.port = None

    # ------------------------------------------------------------------
    # configuration
    # ------------------------------------------------------------------
    def add_object(self, name, data, generation=None, content_type="application/octet-stream"):
        """Add (or replace) an object. ``data`` may be bytes or str."""
        if isinstance(data, str):
            data = data.encode("utf-8")
        with self.lock:
            if generation is None:
                # monotonic: replacing an object always yields a new generation
                self._generation_counter += 1
                generation = self._generation_counter
            self.objects[name] = _GcsObject(data, int(generation), content_type)

    def set_generation(self, name, generation):
        with self.lock:
            self.objects[name].generation = int(generation)

    def set_object_status(self, name, status):
        """Always answer the download of ``name`` with ``status``."""
        with self.lock:
            self.objects[name].status = status

    def fail_object(self, name, times, status=500):
        """Answer the next ``times`` downloads of ``name`` with ``status``."""
        with self.lock:
            self.objects[name].fail_times = times
            self.objects[name].fail_status = status

    def fail_listing(self, times, status=500):
        with self.lock:
            self.list_fail_times = times
            self.list_status = status

    def set_tokens(self, tokens, accepted=None):
        """Tokens handed out by the metadata endpoint, in order (the last one
        repeats). ``accepted`` is the set of bearer tokens the storage API
        accepts; by default only the most recently issued token is valid."""
        with self.lock:
            self.tokens = list(tokens)
            self.accepted_tokens = None if accepted is None else set(accepted)
            self.token_hits = 0

    # ------------------------------------------------------------------
    # inspection
    # ------------------------------------------------------------------
    def requests_of(self, kind):
        with self.lock:
            return [r for r in self.requests if r["kind"] == kind]

    def token_requests(self):
        return self.requests_of("token")

    def list_requests(self):
        return self.requests_of("list")

    def object_requests(self, name=None):
        found = self.requests_of("object")
        if name is not None:
            found = [r for r in found if r["name"] == name]
        return found

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def start(self, port, host="127.0.0.1"):
        handler = self._make_handler()
        self.port = port
        self._httpd = ThreadingHTTPServer((host, port), handler)
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
        if self._thread is not None:
            self._thread.join(timeout=5)
            self._thread = None

    # ------------------------------------------------------------------
    # request handling
    # ------------------------------------------------------------------
    def _current_token(self):
        index = min(max(self.token_hits - 1, 0), len(self.tokens) - 1)
        return self.tokens[index]

    def _authorized(self, headers):
        auth = headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        token = auth[len("Bearer "):]
        if self.accepted_tokens is not None:
            return token in self.accepted_tokens
        return token == self._current_token()

    def _list(self, query):
        prefix = query.get("prefix", [""])[0]
        start = query.get("startOffset", [None])[0]
        end = query.get("endOffset", [None])[0]
        page_token = query.get("pageToken", [None])[0]
        max_results = int(query.get("maxResults", ["1000"])[0])

        names = sorted(n for n in self.objects if n.startswith(prefix))
        if start is not None:
            names = [n for n in names if n >= start]
        if end is not None:
            names = [n for n in names if n < end]
        if page_token is not None:
            # opaque token: the last name of the previous page
            names = [n for n in names if n > page_token[len("page:"):]]

        page = names[:max_results]
        body = {"kind": "storage#objects"}
        if len(names) > max_results:
            body["nextPageToken"] = "page:" + page[-1]
        items = [{"name": n,
                  "generation": str(self.objects[n].generation),
                  "size": str(len(self.objects[n].data))} for n in page]
        if items:
            body["items"] = items
        return 200, json.dumps(body).encode("utf-8"), "application/json"

    def _object(self, name, query):
        obj = self.objects.get(name)
        if obj is None:
            return 404, b'{"error":{"code":404,"message":"No such object"}}', "application/json"
        if query.get("alt", [None])[0] != "media":
            return 400, b'{"error":{"code":400,"message":"alt=media required"}}', "application/json"
        if obj.status is not None:
            return obj.status, b'{"error":{"message":"forced"}}', "application/json"
        if obj.fail_times > 0:
            obj.fail_times -= 1
            return obj.fail_status, b'{"error":{"message":"transient"}}', "application/json"
        generation = query.get("generation", [None])[0]
        if generation is not None and int(generation) != obj.generation:
            return 404, b'{"error":{"code":404,"message":"generation not found"}}', "application/json"
        return 200, obj.data, obj.content_type

    def _handle(self, handler):
        parts = urlsplit(handler.path)
        query = parse_qs(parts.query, keep_blank_values=True)
        record = {
            "method": handler.command,
            "path": parts.path,
            "raw_path": handler.path,
            "query": query,
            "headers": dict(handler.headers),
            "kind": "other",
            "name": None,
            "time": time.monotonic(),
        }
        list_path = f"/storage/v1/b/{self.bucket}/o"
        object_prefix = list_path + "/"

        with self.lock:
            if parts.path == TOKEN_PATH:
                record["kind"] = "token"
                self.token_hits += 1
                if self.token_status != 200:
                    status, body, ctype = self.token_status, b"{}", "application/json"
                else:
                    body = json.dumps({"access_token": self._current_token(),
                                       "expires_in": 3599,
                                       "token_type": "Bearer"}).encode("utf-8")
                    status, ctype = 200, "application/json"
            elif parts.path == list_path or parts.path.startswith(object_prefix):
                is_list = parts.path == list_path
                record["kind"] = "list" if is_list else "object"
                if not is_list:
                    record["name"] = unquote(parts.path[len(object_prefix):])
                if not self._authorized(handler.headers):
                    status, body, ctype = 401, b'{"error":{"code":401}}', "application/json"
                elif is_list and self.list_fail_times > 0:
                    self.list_fail_times -= 1
                    status, body, ctype = self.list_status, b"{}", "application/json"
                elif is_list:
                    status, body, ctype = self._list(query)
                else:
                    status, body, ctype = self._object(record["name"], query)
            else:
                status, body, ctype = 404, b"{}", "application/json"

            record["status"] = status
            self.requests.append(record)

        handler.send_response(status)
        handler.send_header("Content-Type", ctype)
        handler.send_header("Content-Length", str(len(body)))
        handler.end_headers()
        handler.wfile.write(body)

    def _make_handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "FakeGCS/1.0"
            protocol_version = "HTTP/1.1"

            def do_GET(self):
                try:
                    server._handle(self)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, fmt, *args):
                logger.debug("Fake GCS server: %s", fmt % args)

        return Handler
