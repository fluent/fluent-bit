#!/usr/bin/env python3
"""Serve the Fluent Bit WASM test page with browser isolation headers."""

import argparse
from contextlib import ExitStack
import functools
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import os
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit
from browser_receiver import ReceiverHandler, ReceiverState


WEB_DIR = Path(__file__).resolve().parent / "web"
SDK_VERSION = (Path(__file__).resolve().parents[2] / ".emscripten-version").read_text().strip()
DEFAULT_BUILD_DIR = Path(f"build-wasm-{SDK_VERSION}-release")
TARGETS = ("flb-wasm-yaml", "flb-wasm-pipeline", "flb-wasm-storage", "flb-wasm-demo")


class BrowserHandler(ReceiverHandler, SimpleHTTPRequestHandler):
    def __init__(self, *args, build_dir, **kwargs):
        self.build_dir = Path(build_dir).resolve()
        super().__init__(*args, **kwargs)

    def end_headers(self):
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def send_head(self):
        route = self.receiver_route()
        if route and route[1] == 'received':
            if not self.receiver_origin_allowed():
                self.send_error(403)
            else:
                self.receiver_json(200, self.server.receiver.read(route[2]))
            return None
        # Serve only page assets and named test binaries, never the source or
        # build directory wholesale (which may contain unrelated local files).
        routes = {"/": WEB_DIR / "index.html"}
        for name in ("app.js", "style.css", "runner.html", "runner.js", "demo-sdk-worker.js"):
            routes["/" + name] = WEB_DIR / name
        routes["/processors.yaml"] = WEB_DIR.parent / "data" / "processors.yaml"
        routes["/demo.yaml"] = WEB_DIR.parent / "data" / "demo.yaml"
        routes["/demo-lua.yaml"] = WEB_DIR.parent / "data" / "demo-lua.yaml"
        routes["/demo-http.yaml"] = WEB_DIR.parent / "data" / "demo-http.yaml"
        for target in TARGETS:
            for extension in ("js", "wasm"):
                name = f"{target}.{extension}"
                routes["/bin/" + name] = self.build_dir / "bin" / name

        for name in ("fluent-bit.js", "fluent-bit-worker.js", "fluent-bit-pthread.js", "fluent-bit-runtime.js",
                     "fluent-bit-runtime.wasm", "fluent-bit.d.ts"):
            routes["/sdk/" + name] = self.build_dir / "sdk" / "browser" / name

        path = routes.get(urlsplit(self.path).path)
        if path is None:
            self.send_error(404, "Unknown test asset")
            return None
        try:
            file = path.open("rb")
        except OSError:
            self.send_error(404, "Test asset missing; build the selected WASM target first")
            return None
        self.send_response(200)
        mime = "application/wasm" if path.suffix == ".wasm" else self.guess_type(str(path))
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(path.stat().st_size))
        self.end_headers()
        return file

    def log_message(self, format, *args):
        pass

    do_PUT = ReceiverHandler.do_POST


class TLSServer(ThreadingHTTPServer):
    def __init__(self, *args, tls_context, **kwargs):
        self.tls_context = tls_context
        super().__init__(*args, **kwargs)

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(10)
        try:
            # Handshake on the handler thread, not the listener: a plain or
            # stalled connection must not block other HTTPS clients.
            connection = self.tls_context.wrap_socket(
                connection, server_side=True, do_handshake_on_connect=False)
        except Exception:
            connection.close()
            raise
        return connection, address


def create_server(build_dir, port=8088, host="127.0.0.1", tls_context=None, cors_origins=()):
    handler = functools.partial(BrowserHandler, build_dir=build_dir)
    if tls_context is not None:
        server = TLSServer((host, port), handler, tls_context=tls_context)
    else:
        server = ThreadingHTTPServer((host, port), handler)
    server.receiver = ReceiverState(cors_origins)
    return server


def certificate_host(value):
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if len(value) > 253 or not all(
                re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                for label in value.split(".")):
            raise ValueError(f"Invalid certificate hostname or IP address: {value!r}")
        return value.lower()


def development_certificate(build_dir, hosts):
    hosts = sorted({certificate_host(host) for host in hosts})
    identity = hashlib.sha256("\n".join(hosts).encode()).hexdigest()[:20]
    root = Path(build_dir).resolve() / ".browser-tls"
    directory = root / identity
    cert, key = directory / "cert.pem", directory / "key.pem"
    if cert.is_file() and key.is_file():
        return cert, key
    if directory.exists():
        raise ValueError(f"Incomplete TLS certificate directory: {directory}; supply --cert and --key")
    openssl = shutil.which("openssl")
    if not openssl:
        raise ValueError("OpenSSL is required to generate a development certificate; supply --cert and --key")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    names = []
    for host in hosts:
        try:
            ipaddress.ip_address(host)
            names.append("IP:" + host)
        except ValueError:
            names.append("DNS:" + host)
    with tempfile.TemporaryDirectory(prefix=".creating-", dir=root) as temporary:
        staging = Path(temporary)
        subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-sha256", "-nodes",
            "-days", "365", "-subj", "/CN=Fluent Bit WASM development",
            "-addext", "subjectAltName=" + ",".join(names),
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(staging / "key.pem"), "-out", str(staging / "cert.pem")
        ], check=True, capture_output=True)
        (staging / "key.pem").chmod(0o600)
        # Publish the pair together and never overwrite an existing key.
        try:
            os.rename(staging, directory)
        except OSError:
            if not (cert.is_file() and key.is_file()):
                raise
    return cert, key


def server_tls_context(cert, key):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=cert, keyfile=key)
    return context


def create_redirect_server(host, port, https_port, allowed_hosts):
    allowed_hosts = {certificate_host(name) for name in allowed_hosts}

    class RedirectHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            try:
                values = self.headers.get_all("Host", [])
                if len(values) != 1:
                    raise ValueError("Exactly one Host header required")
                authority = urlsplit("http://" + values[0])
                name = certificate_host(authority.hostname or "")
                if (authority.username is not None or authority.password is not None or
                        authority.path or authority.query or authority.fragment or
                        name not in allowed_hosts or
                        not self.path.startswith("/") or self.path.startswith("//") or
                        any(ord(character) < 32 for character in values[0] + self.path)):
                    raise ValueError("Unrecognized redirect host or request path")
                authority.port  # Validate a supplied port, but never copy it.
            except ValueError as error:
                self.send_error(400, str(error))
                return
            if ":" in name:
                name = f"[{name}]"
            self.send_response(307)
            self.send_header("Location", f"https://{name}:{https_port}{self.path}")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True

        do_HEAD = do_GET
        do_POST = do_GET

        def log_message(self, format, *args):
            pass

    return ThreadingHTTPServer((host, port), RedirectHandler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-dir", type=Path, default=DEFAULT_BUILD_DIR)
    parser.add_argument("--port", type=int, default=8443, help="HTTPS port (default: 8443)")
    parser.add_argument("--http-port", type=int, default=8088, help="HTTP redirect port (default: 8088)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (use 0.0.0.0 for all IPv4 interfaces)")
    parser.add_argument("--cert", type=Path, help="Existing PEM certificate or chain")
    parser.add_argument("--key", type=Path, help="Existing PEM private key")
    parser.add_argument("--cert-host", action="append", default=[],
                        help="Additional DNS name or IP for certificate and redirects; repeat as needed")
    args = parser.parse_args()
    if not all(0 <= port <= 65535 for port in (args.port, args.http_port)):
        parser.error("Ports must be between 0 and 65535")
    if args.port == args.http_port and args.port != 0:
        parser.error("HTTPS and HTTP redirect ports must differ")
    if bool(args.cert) != bool(args.key):
        parser.error("--cert and --key must be supplied together")
    try:
        hosts = {"localhost", "127.0.0.1", *args.cert_host}
        if args.host != "0.0.0.0":
            hosts.add(args.host)
        hosts = {certificate_host(host) for host in hosts}
        cert, key = (args.cert, args.key) if args.cert else development_certificate(args.build_dir, hosts)
        context = server_tls_context(cert, key)
        with ExitStack() as stack:
            server = stack.enter_context(create_server(args.build_dir, args.port, args.host, context))
            redirect = stack.enter_context(create_redirect_server(
                args.host, args.http_port, server.server_port, hosts))
            thread = threading.Thread(target=redirect.serve_forever, daemon=True)
            thread.start()
            print(f"HTTPS listening on {server.server_address[0]}:{server.server_port}", flush=True)
            print(f"HTTP redirect listening on {redirect.server_address[0]}:{redirect.server_port}", flush=True)
            for host in sorted(hosts):
                print(f"Open https://{host}:{server.server_port}/", flush=True)
            print(f"Certificate: {cert}", flush=True)
            if not args.cert:
                print("Self-signed development certificate: trust it on each client or supply a trusted "
                      "--cert/--key pair. No trust stores have been modified.", flush=True)
            print(f"WASM build: {args.build_dir.resolve()}\nPress Ctrl+C to stop.", flush=True)
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                pass
            finally:
                redirect.shutdown()
                thread.join()
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Cannot start local server: {error}\n")


if __name__ == "__main__":
    main()
