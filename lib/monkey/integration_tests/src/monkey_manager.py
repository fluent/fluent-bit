from __future__ import annotations

import http.client
import os
import re
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
ENV_MONKEY_BIN_PLAIN = "MONKEY_BIN_PLAIN"
ENV_MONKEY_BIN_OPENSSL = "MONKEY_BIN_OPENSSL"
ENV_MONKEY_BIN_MBEDTLS = "MONKEY_BIN_MBEDTLS"
ENV_MONKEY_VALGRIND = "MONKEY_VALGRIND"
ENV_MONKEY_VALGRIND_STRICT = "MONKEY_VALGRIND_STRICT"


def generate_tls_assets(directory: Path) -> None:
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(directory / "rsa_key.pem"),
            "-out",
            str(directory / "srv_cert.pem"),
            "-sha256",
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=127.0.0.1",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    subprocess.run(
        [
            "openssl",
            "dhparam",
            "-out",
            str(directory / "dhparam.pem"),
            "512",
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    shutil.copy2(directory / "rsa_key.pem", directory / "rsa.pem")


def find_available_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout

    while time.time() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((host, port)) == 0:
                return
        time.sleep(0.1)

    raise TimeoutError(f"Timed out waiting for {host}:{port}")


def replace_config_value(config_text: str, key: str, value: str) -> str:
    pattern = rf"^(\s*{re.escape(key)}\s+).*$"
    updated, count = re.subn(pattern, rf"\g<1>{value}", config_text, count=1, flags=re.MULTILINE)
    if count != 1:
        raise AssertionError(f"Could not replace config key: {key}")
    return updated


@dataclass
class MonkeyBinary:
    label: str
    env_var: str
    tls: bool


@dataclass
class HttpResponse:
    status: int
    reason: str
    headers: dict[str, str]
    body: bytes


class MonkeyManager:
    def __init__(self, binary_path: str, tls: bool = False) -> None:
        self.binary_path = Path(binary_path).resolve()
        self.tls = tls
        self.host = "127.0.0.1"
        self.port = find_available_port()
        self.workdir_obj = tempfile.TemporaryDirectory(prefix="monkey-it-")
        self.workdir = Path(self.workdir_obj.name)
        self.confdir = self.workdir / "conf"
        self.htdocs = self.workdir / "htdocs"
        self.log_file = self.workdir / "monkey.log"
        self.valgrind_log_file = self.workdir / "valgrind.log"
        self.process: subprocess.Popen[str] | None = None
        self.valgrind_enabled = os.environ.get(ENV_MONKEY_VALGRIND) == "1"
        self.valgrind_strict = os.environ.get(ENV_MONKEY_VALGRIND_STRICT) == "1"

    def _read_log_file(self) -> str:
        if not self.log_file.exists():
            return ""
        return self.log_file.read_text(encoding="utf-8", errors="replace")

    @property
    def build_root(self) -> Path:
        return self.binary_path.parent.parent

    @property
    def url(self) -> str:
        scheme = "https" if self.tls else "http"
        return f"{scheme}://{self.host}:{self.port}/"

    def _copy_build_conf(self, filename: str) -> None:
        src = self.build_root / "conf" / filename
        if not src.is_file():
            raise FileNotFoundError(f"Missing config asset: {src}")
        shutil.copy2(src, self.confdir / filename)

    def _prepare_tls_assets(self) -> None:
        self._copy_build_conf("tls.conf")
        generate_tls_assets(self.confdir)

    def prepare(self) -> None:
        self.confdir.mkdir(parents=True, exist_ok=True)
        self.htdocs.mkdir(parents=True, exist_ok=True)
        (self.htdocs / "index.html").write_text(
            "Monkey integration test payload\n",
            encoding="utf-8",
        )

        self._copy_build_conf("monkey.mime")
        if self.tls:
            self._prepare_tls_assets()

        listen_flags = " tls" if self.tls else ""
        monkey_conf = (
            "[SERVER]\n"
            f"    Listen {self.host}:{self.port}{listen_flags}\n"
            "    Workers 1\n"
            "    Timeout 15\n"
            f"    PidFile {self.workdir / 'monkey.pid'}\n"
            "    User root\n"
            "    UserDir disabled\n"
            "    Indexfile index.html\n"
            "    HideVersion Off\n"
            "    Resume On\n"
            "    KeepAlive On\n"
            "    KeepAliveTimeout 5\n"
            "    MaxKeepAliveRequest 50\n"
            "    MaxRequestSize 32\n"
            "    SymLink Off\n"
            "    DefaultMimeType text/plain\n"
            "    FDT On\n"
            "    OverCapacity Resist\n"
        )
        (self.confdir / "monkey.conf").write_text(monkey_conf, encoding="utf-8")

    def _build_command(self) -> list[str]:
        command = [
            str(self.binary_path),
            "-c",
            str(self.confdir),
            "-s",
            "monkey.conf",
            "-o",
            str(self.htdocs),
        ]

        if not self.valgrind_enabled:
            return command

        valgrind_command = [
            "valgrind",
            f"--log-file={self.valgrind_log_file}",
            "--leak-check=full",
            "--show-leak-kinds=all",
            "--track-origins=yes",
            "--error-exitcode=99",
        ]

        if self.valgrind_strict:
            valgrind_command.append("--errors-for-leak-kinds=definite,possible,indirect")

        valgrind_command.extend(command)
        return valgrind_command

    def start(self) -> None:
        self.prepare()
        log_handle = self.log_file.open("w", encoding="utf-8")
        self.process = subprocess.Popen(
            self._build_command(),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        try:
            wait_for_port(self.host, self.port)
        except TimeoutError as exc:
            log_handle.flush()
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"Monkey exited before listening.\n{self._read_log_file()}"
                ) from exc
            raise RuntimeError(
                f"Monkey did not start listening in time.\n{self._read_log_file()}"
            ) from exc

    def _validate_valgrind(self, return_code: int) -> None:
        if not self.valgrind_enabled:
            return

        if return_code == 99:
            raise AssertionError(self.valgrind_log_file.read_text(encoding="utf-8"))

    def stop(self) -> None:
        if self.process is not None:
            self.process.terminate()
            try:
                return_code = self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                return_code = self.process.wait(timeout=5)

            self._validate_valgrind(return_code)
            self.process = None

        self.workdir_obj.cleanup()

    def fetch(self) -> tuple[int, bytes, dict[str, str]]:
        response = self.request("GET", "/", headers={"Connection": "close"})
        return response.status, response.body, response.headers

    def open_http_connection(self) -> http.client.HTTPConnection:
        if self.tls:
            context = ssl._create_unverified_context()
            return http.client.HTTPSConnection(self.host, self.port, timeout=5, context=context)
        return http.client.HTTPConnection(self.host, self.port, timeout=5)

    def request(
        self,
        method: str,
        path: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> HttpResponse:
        connection = self.open_http_connection()
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            payload = response.read()
            response_headers = {k.lower(): v for k, v in response.getheaders()}
            return HttpResponse(response.status, response.reason, response_headers, payload)
        finally:
            connection.close()

    def request_keepalive_sequence(
        self,
        requests_spec: list[tuple[str, str, dict[str, str] | None]],
    ) -> list[HttpResponse]:
        connection = self.open_http_connection()
        responses = []

        try:
            for method, path, headers in requests_spec:
                connection.request(method, path, headers=headers or {})
                response = connection.getresponse()
                payload = response.read()
                response_headers = {k.lower(): v for k, v in response.getheaders()}
                responses.append(HttpResponse(response.status, response.reason, response_headers, payload))
        finally:
            connection.close()

        return responses

    def raw_request(self, payload: bytes) -> bytes:
        return self.raw_request_parts([payload])

    def raw_request_parts(
        self,
        payloads: list[bytes],
        pause_between_parts: float = 0.0,
        shutdown_write: bool = False,
    ) -> bytes:
        sock = socket.create_connection((self.host, self.port), timeout=5)
        sock.settimeout(5)

        if self.tls:
            context = ssl._create_unverified_context()
            sock = context.wrap_socket(sock, server_hostname=self.host)

        try:
            for index, payload in enumerate(payloads):
                sock.sendall(payload)
                if pause_between_parts > 0 and index + 1 < len(payloads):
                    time.sleep(pause_between_parts)

            if shutdown_write:
                try:
                    sock.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

            chunks = []
            while True:
                try:
                    data = sock.recv(65535)
                except ConnectionResetError:
                    break
                except socket.timeout:
                    break

                if not data:
                    break
                chunks.append(data)

            return b"".join(chunks)
        finally:
            sock.close()
