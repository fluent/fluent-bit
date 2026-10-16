import contextlib
import http.server
import os
import shlex
import ssl
import sys
import threading

import pytest
import yaml

from utils.data_utils import read_file
from utils.test_service import FluentBitTestService


class _KubeApiHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b"{}"
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


@contextlib.contextmanager
def _run_kube_api_server():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _KubeApiHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        yield port
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class _PodAssociationServer(http.server.ThreadingHTTPServer):
    def __init__(self, server_address, handler_class):
        super().__init__(server_address, handler_class)
        self.request_count = 0
        self.request_count_lock = threading.Lock()


class _PodAssociationHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        payload = b"{}"

        with self.server.request_count_lock:
            self.server.request_count += 1

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, fmt, *args):
        return


@contextlib.contextmanager
def _run_pod_association_server(cert_file, key_file):
    server = _PodAssociationServer(("127.0.0.1", 0), _PodAssociationHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert_file, key_file)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


class Service:
    def __init__(self, config_file):
        self.config_file = os.path.abspath(config_file)
        self.service = FluentBitTestService(self.config_file)

    def start(self):
        self.service.start()
        self.flb = self.service.flb

    def stop(self):
        self.service.stop()

    def wait_for_log_contains(self, text, timeout=20):
        return self.service.wait_for_condition(
            lambda: read_file(self.flb.log_file) if text in read_file(self.flb.log_file) else None,
            timeout=timeout,
            interval=0.5,
            description=f"log text {text!r}",
        )

    def read_log(self):
        return read_file(self.flb.log_file)


def _write_script(tmp_path, name, line_count):
    script_file = tmp_path / name
    script_file.write_text(
        f"import sys\nsys.stdout.write('tkn\\n' * {line_count})\n",
        encoding="utf-8",
    )
    return script_file


def _write_config(tmp_path, name, script_file, kube_api_port):
    docker_id = "a" * 64
    token_command = "{} {}".format(
        shlex.quote(sys.executable),
        shlex.quote(str(script_file)),
    )

    config_file = tmp_path / name
    config_file.write_text(
        "\n".join(
            [
                "[SERVICE]",
                "    Flush 1",
                "    Grace 1",
                "    Log_Level info",
                "    HTTP_Server On",
                "    HTTP_Port ${FLUENT_BIT_HTTP_MONITORING_PORT}",
                "",
                "[INPUT]",
                "    Name dummy",
                "    Dummy {\"message\":\"kube token command test\"}",
                f"    Tag kube.var.log.containers.testpod_default_testcontainer-{docker_id}.log",
                "    Samples 1",
                "",
                "[FILTER]",
                "    Name kubernetes",
                "    Match kube.*",
                f"    Kube_URL http://127.0.0.1:{kube_api_port}",
                "    Kube_Tag_Prefix kube.var.log.containers.",
                "    tls.verify Off",
                f"    Kube_Token_Command {token_command}",
                "",
                "[OUTPUT]",
                "    Name stdout",
                "    Match *",
            ]
        ),
        encoding="utf-8",
    )
    return config_file


def _write_pod_association_config(tmp_path, servers, cert_file, key_file):
    config_lines = [
        "[SERVICE]",
        "    Flush 1",
        "    Grace 1",
        "    Log_Level info",
        "    HTTP_Server On",
        "    HTTP_Port ${FLUENT_BIT_HTTP_MONITORING_PORT}",
        "",
        "[INPUT]",
        "    Name dummy",
        "    Tag application.test",
        "    Samples 1",
        "",
        "[INPUT]",
        "    Name dummy",
        "    Tag dataplane.test",
        "    Samples 1",
        "",
    ]

    for match, server in zip(("application.*", "dataplane.*"), servers):
        config_lines.extend(
            [
                "[FILTER]",
                "    Name kubernetes",
                f"    Match {match}",
                "    Dummy_Meta On",
                "    Use_Pod_Association On",
                "    AWS_Pod_Association_Host 127.0.0.1",
                f"    AWS_Pod_Association_Port {server.server_address[1]}",
                "    AWS_Pod_Service_Map_Refresh_Interval 1",
                "    AWS_Pod_Association_Host_TLS_Verify Off",
                f"    AWS_Pod_Association_Host_Server_CA_File {cert_file}",
                f"    AWS_Pod_Association_Host_Client_Cert_File {cert_file}",
                f"    AWS_Pod_Association_Host_Client_Key_File {key_file}",
                "",
            ]
        )

    config_lines.extend(
        [
            "[OUTPUT]",
            "    Name null",
            "    Match *",
        ]
    )

    config_file = tmp_path / "pod_association_multiple_filters.conf"
    config_file.write_text("\n".join(config_lines), encoding="utf-8")
    return config_file


@pytest.mark.skipif(sys.platform != "linux", reason="Kube_Token_Command test is Linux-only")
def test_filter_kubernetes_token_command_accepts_multiline_output_over_8kb(tmp_path):
    script_file = _write_script(tmp_path, "token_large.py", 3000)
    with _run_kube_api_server() as kube_api_port:
        config_file = _write_config(tmp_path, "token_large.conf", script_file, kube_api_port)

        service = Service(str(config_file))
        service.start()
        log_text = service.wait_for_log_contains("kube token command test", timeout=25)
        service.stop()

    assert "failed to run command" not in log_text
    assert "kube token command test" in log_text


@pytest.mark.skipif(sys.platform != "linux", reason="Kube_Token_Command test is Linux-only")
def test_filter_kubernetes_token_command_rejects_multiline_output_over_limit(tmp_path):
    script_file = _write_script(tmp_path, "token_huge.py", 270000)
    with _run_kube_api_server() as kube_api_port:
        config_file = _write_config(tmp_path, "token_huge.conf", script_file, kube_api_port)

        service = Service(str(config_file))
        log_text = None
        service.start()
        try:
            log_text = service.wait_for_log_contains("failed to run command", timeout=25)
            log_text = service.wait_for_log_contains("kube token command test", timeout=25)
        finally:
            service.stop()

    assert "failed to run command" in log_text
    assert "kube token command test" in log_text


def test_filter_kubernetes_pod_association_is_independent_per_instance(tmp_path):
    cert_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "../../in_splunk/certificate")
    )
    cert_file = os.path.join(cert_dir, "certificate.pem")
    key_file = os.path.join(cert_dir, "private_key.pem")

    with _run_pod_association_server(cert_file, key_file) as application_server, \
            _run_pod_association_server(cert_file, key_file) as dataplane_server:
        servers = (application_server, dataplane_server)
        config_file = _write_pod_association_config(
            tmp_path, servers, cert_file, key_file
        )
        service = Service(str(config_file))
        service.start()
        try:
            service.service.wait_for_condition(
                lambda: all(server.request_count >= 2 for server in servers),
                timeout=20,
                interval=0.25,
                description="two refreshes from each pod association filter",
            )
        finally:
            service.stop()

    assert all(server.request_count >= 2 for server in servers)


@pytest.mark.parametrize("custom_parser", [False, True])
@pytest.mark.parametrize("namespace_only", [False, True])
def test_filter_kubernetes_rejects_unsafe_tag_names(tmp_path, custom_parser, namespace_only):
    requests = []

    class Handler(_KubeApiHandler):
        def do_GET(self):
            requests.append((self.path, self.headers.get("Authorization")))
            super().do_GET()

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    token_file = tmp_path / "token"
    token_file.write_text("regression-token", encoding="utf-8")
    parser_file = tmp_path / "parsers.conf"
    parser_file.write_text(
        "[PARSER]\n    Name capture\n    Format regex\n"
        "    Regex ^(?<pod_name>[^_]+)_(?<namespace_name>[^_]+)_"
        "(?<container_name>.+)-(?<docker_id>[a-z0-9]{64})\\.log$\n",
        encoding="utf-8",
    )
    invalid = [
        "../secrets", "default/pods", "default?watch=true", "default#fragment",
        "default%2fsecrets", "default space", "default\tvalue",
        "default\r\nX-Injected: yes", "default\x00suffix", ".", "..",
        "UPPER", "-default", "default-", "default.name", "n" * 64,
    ]
    valid = [("pod-0.example", "default"), ("p" * 253, "n" * 63), ("0", "1")]
    cases = [("pod", name) for name in invalid]
    if custom_parser:
        cases += [(name, "default") for name in invalid if name not in ("default.name", "n" * 64)]
        cases += [("p" * 254, "default"), ("pod..name", "default"), ("pod.", "default")]
    cases += valid
    inputs = [
        {
            "name": "dummy", "samples": 1,
            "tag": f"kube.var.log.containers.{pod}_{namespace}_container-{'a' * 64}.log",
            "dummy": '{"message":"tag-name-case-%d"}' % index,
        }
        for index, (pod, namespace) in enumerate(cases)
    ]
    kube_filter = {
        "name": "kubernetes", "match": "kube.*",
        "kube_url": f"http://127.0.0.1:{server.server_address[1]}",
        "kube_token_file": str(token_file), "kube_meta_namespace_cache_ttl": "0",
        "kube_meta_cache_ttl": "0", "kube_tag_prefix": "kube.var.log.containers.",
        "namespace_labels": True, "namespace_metadata_only": namespace_only,
    }
    if custom_parser:
        kube_filter["regex_parser"] = "capture"
    config = {
        "service": {"flush": 1, "grace": 1, "log_level": "info",
                    "parsers_file": str(parser_file), "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {"inputs": inputs, "filters": [kube_filter],
                     "outputs": [{"name": "stdout", "match": "*"}]},
    }
    config_file = tmp_path / "tag-names.yaml"
    config_file.write_text(yaml.safe_dump(config), encoding="utf-8")
    service = Service(str(config_file))
    try:
        service.start()
        service.service.wait_for_condition(
            lambda: all(f'"tag-name-case-{index}"' in service.read_log()
                        for index in range(len(cases))),
            timeout=30, interval=0.25, description="all tag validation records flushed",
        )
    finally:
        service.stop()
        server.shutdown()
        server.server_close()
        thread.join()

    expected = {f"/api/v1/namespaces/{namespace}" for _, namespace in valid}
    if not namespace_only:
        expected.update(f"/api/v1/namespaces/{namespace}/pods/{pod}"
                        for pod, namespace in valid)
    assert {path for path, _ in requests} == expected
    assert len(requests) == len(expected)
    assert all(auth == "Bearer regression-token" for _, auth in requests)
