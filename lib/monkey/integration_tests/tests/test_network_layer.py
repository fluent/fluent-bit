from __future__ import annotations

import shutil
import subprocess
import os
from pathlib import Path

import pytest

from src.monkey_manager import ENV_MONKEY_BIN_MBEDTLS
from src.monkey_manager import ENV_MONKEY_BIN_OPENSSL
from src.monkey_manager import ENV_MONKEY_BIN_PLAIN
from src.monkey_manager import find_available_port
from src.monkey_manager import generate_tls_assets
from src.monkey_manager import MonkeyBinary
from src.monkey_manager import MonkeyManager
from src.monkey_manager import replace_config_value
from src.monkey_manager import wait_for_port


BINARIES = [
    MonkeyBinary("plain", ENV_MONKEY_BIN_PLAIN, False),
    MonkeyBinary("openssl", ENV_MONKEY_BIN_OPENSSL, True),
    MonkeyBinary("mbedtls", ENV_MONKEY_BIN_MBEDTLS, True),
]


def resolve_binary(candidate: MonkeyBinary) -> str:
    path = os.environ.get(candidate.env_var)
    if not path:
        defaults = {
            ENV_MONKEY_BIN_PLAIN: "/tmp/monkey-build-default/bin/monkey",
            ENV_MONKEY_BIN_OPENSSL: "/tmp/monkey-build-tls/bin/monkey",
            ENV_MONKEY_BIN_MBEDTLS: "/tmp/monkey-build-mbedtls/bin/monkey",
        }
        path = defaults[candidate.env_var]

    if not Path(path).is_file():
        pytest.skip(f"{candidate.label} binary not available: {path}")

    return path


def selected_binaries() -> list[MonkeyBinary]:
    selection = os.environ.get("MONKEY_TEST_BINARIES", "all")
    if selection == "all":
        return BINARIES

    return [candidate for candidate in BINARIES if candidate.label == selection]


@pytest.fixture(params=selected_binaries(), ids=lambda item: item.label)
def monkey_instance(request):
    candidate = request.param
    manager = MonkeyManager(resolve_binary(candidate), tls=candidate.tls)
    manager.start()
    try:
        yield manager
    finally:
        manager.stop()


def test_serves_index_body(monkey_instance: MonkeyManager):
    status, body, headers = monkey_instance.fetch()

    assert status == 200
    assert body == b"Monkey integration test payload\n"
    assert headers["content-type"].startswith("text/html")
    assert int(headers["content-length"]) == len(body)


def test_server_header_present(monkey_instance: MonkeyManager):
    status, _, headers = monkey_instance.fetch()

    assert status == 200
    assert headers["server"].startswith("Monkey/")


def test_forbidden_error_page_escapes_reflected_uri(monkey_instance: MonkeyManager):
    payload = b"GET /../\"><script>alert(73541);</script> HTTP/1.1\r\n"
    payload += f"Host: {monkey_instance.host}:{monkey_instance.port}\r\n".encode()
    payload += b"Connection: close\r\n\r\n"

    response = monkey_instance.raw_request(payload)

    assert b"HTTP/1.1 403 Forbidden" in response
    assert b"<script>alert(73541);</script>" not in response
    assert b"/../&quot;&gt;&lt;script&gt;alert(73541);&lt;/script&gt;" in response


def test_server_restarts_cleanly():
    for candidate in selected_binaries():
        manager = MonkeyManager(resolve_binary(candidate), tls=candidate.tls)
        manager.start()
        try:
            status, body, _ = manager.fetch()
            assert status == 200
            assert body == b"Monkey integration test payload\n"
        finally:
            manager.stop()


        manager = MonkeyManager(resolve_binary(candidate), tls=candidate.tls)
        manager.start()
        try:
            status, body, _ = manager.fetch()
            assert status == 200
            assert body == b"Monkey integration test payload\n"
        finally:
            manager.stop()


def test_binary_starts_with_no_arguments_from_build_tree(tmp_path: Path):
    plain_binary = resolve_binary(MonkeyBinary("plain", ENV_MONKEY_BIN_PLAIN, False))
    build_root = Path(plain_binary).resolve().parent.parent
    runtime_root = tmp_path / "runtime"
    runtime_bin = runtime_root / "bin"
    runtime_conf = runtime_root / "conf"
    runtime_sites = runtime_conf / "sites"
    runtime_htdocs = runtime_root / "htdocs"
    runtime_run = runtime_root / "run"
    runtime_logs = runtime_root / "logs"
    port = find_available_port()
    log_file = runtime_root / "monkey.log"

    runtime_bin.mkdir(parents=True)
    runtime_sites.mkdir(parents=True)
    runtime_htdocs.mkdir(parents=True)
    runtime_run.mkdir(parents=True)
    runtime_logs.mkdir(parents=True)

    shutil.copy2(build_root / "bin" / "monkey", runtime_bin / "monkey")
    shutil.copy2(build_root / "conf" / "monkey.mime", runtime_conf / "monkey.mime")
    shutil.copy2(build_root / "conf" / "plugins.load", runtime_conf / "plugins.load")

    monkey_conf = (build_root / "conf" / "monkey.conf").read_text(encoding="utf-8")
    monkey_conf = replace_config_value(monkey_conf, "Listen", str(port))
    monkey_conf = replace_config_value(
        monkey_conf, "PidFile", str((runtime_run / "monkey.pid").resolve())
    )
    (runtime_conf / "monkey.conf").write_text(monkey_conf, encoding="utf-8")

    site_conf = (build_root / "conf" / "sites" / "default").read_text(encoding="utf-8")
    site_conf = replace_config_value(
        site_conf, "DocumentRoot", str(runtime_htdocs.resolve())
    )
    site_conf = replace_config_value(
        site_conf, "AccessLog", str((runtime_logs / "access.log").resolve())
    )
    site_conf = replace_config_value(
        site_conf, "ErrorLog", str((runtime_logs / "error.log").resolve())
    )
    (runtime_sites / "default").write_text(site_conf, encoding="utf-8")

    (runtime_htdocs / "index.html").write_text(
        "Monkey direct startup regression\n",
        encoding="utf-8",
    )

    process = None
    log_handle = log_file.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            ["./bin/monkey"],
            cwd=runtime_root,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_port("127.0.0.1", port)

        manager = MonkeyManager(plain_binary, tls=False)
        manager.host = "127.0.0.1"
        manager.port = port
        response = manager.request("GET", "/")
        assert response.status == 200
        assert response.body == b"Monkey direct startup regression\n"
    finally:
        log_handle.flush()
        log_handle.close()
        if process is not None:
            process.terminate()
            process.wait(timeout=5)


def test_binary_https_can_be_enabled_from_cli_without_tls_conf(tmp_path: Path):
    plain_binary = resolve_binary(MonkeyBinary("plain", ENV_MONKEY_BIN_PLAIN, False))
    build_root = Path(plain_binary).resolve().parent.parent
    runtime_root = tmp_path / "runtime-https"
    runtime_bin = runtime_root / "bin"
    runtime_conf = runtime_root / "conf"
    runtime_sites = runtime_conf / "sites"
    runtime_htdocs = runtime_root / "htdocs"
    runtime_run = runtime_root / "run"
    runtime_logs = runtime_root / "logs"
    port = find_available_port()
    log_file = runtime_root / "monkey.log"

    runtime_bin.mkdir(parents=True)
    runtime_sites.mkdir(parents=True)
    runtime_htdocs.mkdir(parents=True)
    runtime_run.mkdir(parents=True)
    runtime_logs.mkdir(parents=True)

    shutil.copy2(build_root / "bin" / "monkey", runtime_bin / "monkey")
    shutil.copy2(build_root / "conf" / "monkey.mime", runtime_conf / "monkey.mime")
    shutil.copy2(build_root / "conf" / "plugins.load", runtime_conf / "plugins.load")

    monkey_conf = (build_root / "conf" / "monkey.conf").read_text(encoding="utf-8")
    monkey_conf = replace_config_value(
        monkey_conf, "PidFile", str((runtime_run / "monkey.pid").resolve())
    )
    (runtime_conf / "monkey.conf").write_text(monkey_conf, encoding="utf-8")

    site_conf = (build_root / "conf" / "sites" / "default").read_text(encoding="utf-8")
    site_conf = replace_config_value(
        site_conf, "DocumentRoot", str(runtime_htdocs.resolve())
    )
    site_conf = replace_config_value(
        site_conf, "AccessLog", str((runtime_logs / "access.log").resolve())
    )
    site_conf = replace_config_value(
        site_conf, "ErrorLog", str((runtime_logs / "error.log").resolve())
    )
    (runtime_sites / "default").write_text(site_conf, encoding="utf-8")

    (runtime_htdocs / "index.html").write_text(
        "Monkey CLI HTTPS regression\n",
        encoding="utf-8",
    )
    generate_tls_assets(runtime_root)

    process = None
    log_handle = log_file.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [
                "./bin/monkey",
                "--https",
                "-p",
                str(port),
                "--tls-cert",
                str((runtime_root / "srv_cert.pem").resolve()),
                "--tls-key",
                str((runtime_root / "rsa_key.pem").resolve()),
                "--tls-dh",
                str((runtime_root / "dhparam.pem").resolve()),
            ],
            cwd=runtime_root,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_port("127.0.0.1", port)

        manager = MonkeyManager(plain_binary, tls=True)
        manager.host = "127.0.0.1"
        manager.port = port
        response = manager.request("GET", "/")
        assert response.status == 200
        assert response.body == b"Monkey CLI HTTPS regression\n"
    finally:
        log_handle.flush()
        log_handle.close()
        if process is not None:
            process.terminate()
            process.wait(timeout=5)


def test_binary_https_without_explicit_certs_uses_builtin_fallback(tmp_path: Path):
    plain_binary = resolve_binary(MonkeyBinary("plain", ENV_MONKEY_BIN_PLAIN, False))
    build_root = Path(plain_binary).resolve().parent.parent
    runtime_root = tmp_path / "runtime-https-fallback"
    runtime_bin = runtime_root / "bin"
    runtime_conf = runtime_root / "conf"
    runtime_sites = runtime_conf / "sites"
    runtime_htdocs = runtime_root / "htdocs"
    runtime_run = runtime_root / "run"
    runtime_logs = runtime_root / "logs"
    port = find_available_port()
    log_file = runtime_root / "monkey.log"

    runtime_bin.mkdir(parents=True)
    runtime_sites.mkdir(parents=True)
    runtime_htdocs.mkdir(parents=True)
    runtime_run.mkdir(parents=True)
    runtime_logs.mkdir(parents=True)

    shutil.copy2(build_root / "bin" / "monkey", runtime_bin / "monkey")
    shutil.copy2(build_root / "conf" / "monkey.mime", runtime_conf / "monkey.mime")
    shutil.copy2(build_root / "conf" / "plugins.load", runtime_conf / "plugins.load")
    shutil.copy2(build_root / "conf" / "tls.conf", runtime_conf / "tls.conf")

    monkey_conf = (build_root / "conf" / "monkey.conf").read_text(encoding="utf-8")
    monkey_conf = replace_config_value(
        monkey_conf, "PidFile", str((runtime_run / "monkey.pid").resolve())
    )
    (runtime_conf / "monkey.conf").write_text(monkey_conf, encoding="utf-8")

    site_conf = (build_root / "conf" / "sites" / "default").read_text(encoding="utf-8")
    site_conf = replace_config_value(
        site_conf, "DocumentRoot", str(runtime_htdocs.resolve())
    )
    site_conf = replace_config_value(
        site_conf, "AccessLog", str((runtime_logs / "access.log").resolve())
    )
    site_conf = replace_config_value(
        site_conf, "ErrorLog", str((runtime_logs / "error.log").resolve())
    )
    (runtime_sites / "default").write_text(site_conf, encoding="utf-8")

    (runtime_htdocs / "index.html").write_text(
        "Monkey CLI HTTPS builtin fallback\n",
        encoding="utf-8",
    )

    process = None
    log_handle = log_file.open("w", encoding="utf-8")
    try:
        process = subprocess.Popen(
            [
                "./bin/monkey",
                "--https",
                "-p",
                str(port),
            ],
            cwd=runtime_root,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
        wait_for_port("127.0.0.1", port)

        manager = MonkeyManager(plain_binary, tls=True)
        manager.host = "127.0.0.1"
        manager.port = port
        response = manager.request("GET", "/")
        assert response.status == 200
        assert response.body == b"Monkey CLI HTTPS builtin fallback\n"
    finally:
        log_handle.flush()
        log_handle.close()
        if process is not None:
            process.terminate()
            process.wait(timeout=5)


def test_head_returns_headers_without_body(monkey_instance: MonkeyManager):
    response = monkey_instance.request("HEAD", "/")

    assert response.status == 200
    assert response.body == b""
    assert int(response.headers["content-length"]) > 0
    assert response.headers["content-type"].startswith("text/html")


def test_missing_resource_returns_404(monkey_instance: MonkeyManager):
    response = monkey_instance.request("GET", "/missing-file")

    assert response.status == 404
    assert b"Not Found" in response.body


def test_path_traversal_returns_403(monkey_instance: MonkeyManager):
    response = monkey_instance.request("GET", "/../etc/passwd")

    assert response.status == 403


def test_encoded_path_traversal_returns_403(monkey_instance: MonkeyManager):
    response = monkey_instance.request("GET", "/%2e%2e/etc/passwd")

    assert response.status == 403


def test_unknown_method_returns_501(monkey_instance: MonkeyManager):
    payload = (
        b"BREW / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    response = monkey_instance.raw_request(payload)

    assert b"HTTP/1.1 501" in response


def test_put_returns_405(monkey_instance: MonkeyManager):
    response = monkey_instance.request("PUT", "/")

    assert response.status == 405


def test_http11_without_host_returns_400(monkey_instance: MonkeyManager):
    payload = (
        b"GET / HTTP/1.1\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )
    response = monkey_instance.raw_request(payload)

    assert b"HTTP/1.1 400" in response


def test_http10_without_host_is_accepted(monkey_instance: MonkeyManager):
    response = monkey_instance.raw_request(
        b"GET / HTTP/1.0\r\n"
        b"\r\n"
    )

    assert b"HTTP/1.1 200 OK" in response


def test_absolute_form_request_target_returns_400(monkey_instance: MonkeyManager):
    response = monkey_instance.raw_request(
        b"GET http://localhost/ HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    assert b"HTTP/1.1 400" in response


def test_keepalive_supports_multiple_requests(monkey_instance: MonkeyManager):
    responses = monkey_instance.request_keepalive_sequence(
        [
            ("GET", "/", {"Connection": "keep-alive"}),
            ("GET", "/", {"Connection": "close"}),
        ]
    )

    assert len(responses) == 2
    assert responses[0].status == 200
    assert responses[1].status == 200
    assert responses[0].body == b"Monkey integration test payload\n"
    assert responses[1].body == b"Monkey integration test payload\n"


def test_pipelined_requests_return_both_responses(monkey_instance: MonkeyManager):
    response = monkey_instance.raw_request(
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: keep-alive\r\n"
        b"\r\n"
        b"GET /missing-file HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    assert response.count(b"HTTP/1.1 ") == 2
    assert b"HTTP/1.1 200 OK" in response
    assert b"HTTP/1.1 404 Not Found" in response


def test_oversized_header_returns_413(monkey_instance: MonkeyManager):
    response = monkey_instance.raw_request(
        b"GET / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"X-Fill: " + (b"a" * 40000) + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    assert b"HTTP/1.1 413" in response


def test_split_request_across_tcp_chunks_is_parsed(monkey_instance: MonkeyManager):
    response = monkey_instance.raw_request_parts(
        [
            b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n",
            b"Connection: close\r\n"
            b"\r\n",
        ],
        pause_between_parts=0.01,
    )

    assert b"HTTP/1.1 200 OK" in response


def test_bad_request_line_returns_400(monkey_instance: MonkeyManager):
    response = monkey_instance.raw_request(
        b"GET noslash HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Connection: close\r\n"
        b"\r\n"
    )

    assert b"HTTP/1.1 400" in response
