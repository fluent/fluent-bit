"""Private-network Kusto protocol fixture. Never use real credentials here."""

import argparse
import json
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def respond(self, status, category, payload=None):
        data = b"" if payload is None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)
        print(json.dumps({"category": category, "status": status}), flush=True)

    def do_GET(self):
        if urlsplit(self.path).path == "/health":
            self.respond(200, "health", {"ready": True})
        else:
            self.respond(404, "unexpected")

    def do_POST(self):
        self.handle_request()

    def do_PUT(self):
        self.handle_request()

    def handle_request(self):
        path = urlsplit(self.path).path
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if self.command == "POST" and path.endswith("/oauth2/v2.0/token"):
            self.respond(200, "oauth", {
                "access_token": "local-only-token",
                "token_type": "Bearer", "expires_in": 3600,
            })
        elif self.command == "POST" and path == "/v1/rest/mgmt":
            try:
                command = json.loads(body)["csl"]
            except (ValueError, KeyError, TypeError):
                self.respond(400, "invalid-command")
                return
            if command == ".get ingestion resources":
                with self.server.state_lock:
                    self.server.loads += 1
                    generation = self.server.loads
                rows = []
                for resource, prefix in [
                    ("TempStorage", "blob"),
                    ("SecuredReadyForAggregationQueue", "queue"),
                ]:
                    for index in range(self.server.args.resources):
                        host = self.server.args.resource_host
                        if self.server.args.split_hosts:
                            host = prefix + ".local"
                        rows.append([
                            resource,
                            f"https://{host}/{prefix}{index}/g{generation}?sig=local-only",
                        ])
                self.respond(200, "resources", {"Tables": [{
                    "TableName": "Table_0",
                    "Columns": [
                        {"ColumnName": "ResourceTypeName", "ColumnType": "string"},
                        {"ColumnName": "StorageRoot", "ColumnType": "string"},
                    ],
                    "Rows": rows,
                }]})
            elif command == ".get kusto identity token":
                with self.server.state_lock:
                    self.server.identities += 1
                    number = self.server.identities
                if self.server.args.fail_identity and number % 3 == 0:
                    self.respond(503, "identity-failure")
                    return
                self.respond(200, "identity", {"Tables": [{
                    "TableName": "Table_0",
                    "Columns": [{
                        "ColumnName": "AuthorizationContext",
                        "DataType": "String", "ColumnType": "string",
                    }],
                    "Rows": [["local-only-identity"]],
                }]})
            else:
                self.respond(400, "unexpected-command")
        elif self.command == "PUT" and path.startswith("/blob"):
            if self.server.args.delay:
                time.sleep(self.server.args.delay)
            self.respond(201, "blob")
        elif self.command == "POST" and path.startswith("/queue"):
            self.respond(201, "queue")
        else:
            self.respond(404, "unexpected")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--resources", type=int, default=20)
    parser.add_argument("--resource-host", default="mock.local")
    parser.add_argument("--split-hosts", action="store_true")
    parser.add_argument("--fail-identity", action="store_true")
    parser.add_argument("--delay", type=float, default=0)
    args = parser.parse_args()
    server = ThreadingHTTPServer(("0.0.0.0", 443), Handler)
    server.args = args
    server.state_lock = threading.Lock()
    server.loads = 0
    server.identities = 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain("/probe/cert.pem", "/probe/key.pem")
    context.set_servername_callback(
        lambda _socket, name, _context: print(
            json.dumps({"category": "sni", "name": name}), flush=True
        )
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
