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

import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


SCHEMA_ID = 42
SCHEMA_SUBJECT = "out-kafka-avro-value"
SCHEMA_VERSION = 3
SCHEMA = {
    "type": "record",
    "name": "out_kafka_avro_record",
    "fields": [
        {"name": "message", "type": "string"},
        {"name": "source", "type": "string"},
    ],
}

data_storage = {"requests": []}
logger = logging.getLogger(__name__)
server_instance = None
server_thread = None


def reset_schema_registry_server_state():
    data_storage["requests"] = []


class SchemaRegistryHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        logger.debug("schema_registry_server: " + fmt, *args)

    def do_GET(self):
        data_storage["requests"].append(
            {
                "path": self.path,
                "headers": dict(self.headers),
                "method": "GET",
            }
        )

        if self.path == f"/subjects/{SCHEMA_SUBJECT}/versions/latest":
            self._send_json(
                {
                    "subject": SCHEMA_SUBJECT,
                    "id": SCHEMA_ID,
                    "version": SCHEMA_VERSION,
                    "schema": json.dumps(SCHEMA, separators=(",", ":")),
                    "schemaType": "AVRO",
                }
            )
            return

        if self.path == f"/schemas/ids/{SCHEMA_ID}":
            self._send_json(
                {
                    "schema": json.dumps(SCHEMA, separators=(",", ":")),
                    "schemaType": "AVRO",
                }
            )
            return

        self._send_json({"error_code": 40403, "message": "Schema not found"}, status=404)

    def _send_json(self, body, status=200):
        payload = json.dumps(body).encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "application/vnd.schemaregistry.v1+json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


def schema_registry_server_run(port, host="127.0.0.1"):
    global server_instance
    global server_thread

    reset_schema_registry_server_state()
    server_instance = ThreadingHTTPServer((host, port), SchemaRegistryHandler)
    server_thread = threading.Thread(target=server_instance.serve_forever, daemon=True)
    server_thread.start()
    return server_thread


def schema_registry_server_stop():
    global server_instance

    if server_instance is not None:
        server_instance.shutdown()
        server_instance.server_close()
        server_instance = None
