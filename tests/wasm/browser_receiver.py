"""Bounded, memory-only HTTPS receiver for the manual WASM playground."""

from collections import OrderedDict, deque
import base64
import json
import re
import ssl
import threading
import time
from urllib.parse import parse_qs, urlsplit


class ReceiverState:
    def __init__(self, cors_origins=()):
        self.lock = threading.Lock()
        self.entries = OrderedDict()
        self.cors_origins = frozenset(cors_origins)

    def record(self, token, request, failures, status):
        with self.lock:
            now = time.monotonic()
            for old in list(self.entries):
                if now - self.entries[old]['time'] > 600:
                    del self.entries[old]
            entry = self.entries.setdefault(token, {'time': now, 'attempts': 0, 'requests': deque(maxlen=20)})
            entry['time'] = now
            entry['attempts'] += 1
            request['status'] = 503 if entry['attempts'] <= failures else status
            entry['requests'].append(request)
            self.entries.move_to_end(token)
            while len(self.entries) > 16:
                self.entries.popitem(last=False)
            return entry['attempts'], request['status']

    def read(self, token):
        with self.lock:
            entry = self.entries.get(token)
            if not entry or time.monotonic() - entry['time'] > 600:
                return {'attempts': 0, 'requests': []}
            return {'attempts': entry['attempts'], 'requests': list(entry['requests'])}


class ReceiverHandler:
    def receiver_route(self):
        return re.fullmatch(r'/(collect|received)/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})',
                            urlsplit(self.path).path)

    def receiver_origin_allowed(self):
        origin = self.headers.get('Origin')
        scheme = 'https' if isinstance(self.connection, ssl.SSLSocket) else 'http'
        return not origin or origin == f'{scheme}://{self.headers.get("Host")}' or origin in self.server.receiver.cors_origins

    def receiver_json(self, status, data):
        encoded = b'' if status == 204 else json.dumps(data, ensure_ascii=True).encode()
        self.send_response(status)
        origin = self.headers.get('Origin')
        if origin and self.receiver_origin_allowed():
            self.send_header('Access-Control-Allow-Origin', origin)
            self.send_header('Vary', 'Origin')
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(encoded)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(encoded)

    def do_OPTIONS(self):
        route = self.receiver_route()
        if not route or route[1] != 'collect':
            self.send_error(404)
            return
        if not self.receiver_origin_allowed():
            self.send_error(403)
            return
        self.send_response(204)
        self.send_header('Access-Control-Allow-Origin', self.headers.get('Origin', 'null'))
        self.send_header('Vary', 'Origin')
        self.send_header('Access-Control-Allow-Methods', 'POST, PUT')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Content-Encoding, Authorization, X-Fluent-Tag, X-Demo')
        self.send_header('Content-Length', '0')
        self.end_headers()

    def do_POST(self):
        route = self.receiver_route()
        if not route or route[1] != 'collect':
            self.send_error(404)
            return
        if not self.receiver_origin_allowed():
            self.send_error(403)
            return
        lengths = self.headers.get_all('Content-Length', [])
        if len(lengths) != 1 or not lengths[0].isdigit() or self.headers.get('Transfer-Encoding'):
            self.send_error(400, 'One Content-Length required; chunked requests are unsupported')
            return
        if len(lengths[0]) > 10:
            self.send_error(413)
            return
        length = int(lengths[0])
        if length > 1024 * 1024:
            self.send_error(413)
            return
        params = parse_qs(urlsplit(self.path).query)
        try:
            failures = int(params.get('fail', ['0'])[0])
            status = int(params.get('status', ['200'])[0])
            delay = float(params.get('delay', ['0'])[0])
            if not 0 <= failures <= 3 or status not in (200, 201, 202, 204, 400, 408, 429, 500, 503) or not 0 <= delay <= 2:
                raise ValueError()
        except ValueError:
            self.send_error(400)
            return
        self.connection.settimeout(5)
        try:
            body = self.rfile.read(length)
            if len(body) != length:
                self.send_error(400)
                return
        except (TimeoutError, OSError):
            self.send_error(408)
            return
        if params.get('auth') == ['1'] and self.headers.get('Authorization') != 'Basic ZGVtbzpkZW1v':
            self.receiver_json(401, {'error': 'Use demo:demo basic credentials for this test'})
            return
        request = {'method': self.command, 'bytes': len(body), 'body': body[:8192].decode('utf-8', errors='replace'),
                   'base64': base64.b64encode(body[:8192]).decode(), 'truncated': len(body) > 8192,
                   'content_type': self.headers.get('Content-Type'), 'encoding': self.headers.get('Content-Encoding'),
                   'tag': self.headers.get('X-Fluent-Tag'), 'demo_header': self.headers.get('X-Demo'),
                   'authorization_present': bool(self.headers.get('Authorization'))}
        attempt, status = self.server.receiver.record(route[2], request, failures, status)
        if delay:
            time.sleep(delay)
        try:
            self.receiver_json(status, {'attempt': attempt, 'accepted': 200 <= status < 300})
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass  # A deliberate timeout/Stop can abort the browser request.
