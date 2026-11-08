"""Untrusted NGINX Plus responses must fail safely and allow later scrapes."""

import copy
import json
import re
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
import requests
import yaml

from utils.network import find_available_port
from utils.test_service import FluentBitTestService


TABLES = [
    "http/server_zones", "http/location_zones", "http/upstreams",
    "stream/server_zones", "stream/upstreams",
]


# These are the scalar fields consumed by the plugin. Unknown API fields remain
# ignored; state is a string enum and is tested separately.
FLAT_FIELDS = {
    "connections": ["accepted", "dropped", "active", "idle"],
    "ssl": ["handshakes", "handshakes_failed", "session_reuses"],
    "http/requests": ["total", "current"],
}
ZONE_FIELDS = {
    "http/server_zones": ["processing", "requests", "discarded", "received", "sent"],
    "http/location_zones": ["requests", "discarded", "received", "sent"],
    "stream/server_zones": ["connections", "processing", "discarded", "received", "sent"],
}
PEER_FIELDS = {
    "http/upstreams": ["active", "fails", "header_time", "limit", "received", "requests",
                       "response_time", "sent", "unavail"],
    "stream/upstreams": ["active", "fails", "limit", "received", "connect_time",
                         "first_byte_time", "connections", "response_time", "sent", "unavail"],
}
UPSTREAM_FIELDS = {"http/upstreams": ["keepalives", "zombies"], "stream/upstreams": ["zombies"]}
STATES = {"up": 1, "draining": 2, "down": 3, "unavail": 4, "checking": 5, "unhealthy": 6}
WRONG_NUMBERS = [1.5, "7", None, True, False, [], {}, -1]


def valid_response(endpoint):
    # Schema-derived fixtures include real state strings and unconsumed fields.
    # See https://nginx.org/en/docs/http/ngx_http_api_module.html
    if endpoint in FLAT_FIELDS:
        result = dict.fromkeys(FLAT_FIELDS[endpoint], 7)
    elif endpoint in ZONE_FIELDS:
        zone = dict.fromkeys(ZONE_FIELDS[endpoint], 7)
        field = "sessions" if endpoint.startswith("stream/") else "responses"
        zone[field] = {f"{code}xx": 3 for code in range(1, 6)}
        result = {"zone": zone}
    elif endpoint in PEER_FIELDS:
        peer = dict.fromkeys(PEER_FIELDS[endpoint], 7)
        peer.update({"server": "127.0.0.1:80", "state": "up", "backup": False,
                     "weight": 1, "health_checks": {"checks": 0}})
        if endpoint.startswith("http/"):
            peer["responses"] = {f"{code}xx": 3 for code in range(1, 6)}
        upstream = dict.fromkeys(UPSTREAM_FIELDS[endpoint], 7)
        upstream["peers"] = [peer]
        result = {"zone": upstream}
    else:
        raise AssertionError(f"Unexpected endpoint: {endpoint}")
    result["future_field"] = {"new": []}
    # Table entries themselves must be maps, including unknown zones.
    return result


def numeric_cases():
    for endpoint, fields in FLAT_FIELDS.items():
        for field in fields:
            yield endpoint, (field,)
    for endpoint, fields in ZONE_FIELDS.items():
        for field in fields:
            yield endpoint, ("zone", field)
        field = "sessions" if endpoint.startswith("stream/") else "responses"
        for code in range(1, 6):
            yield endpoint, ("zone", field, f"{code}xx")
    for endpoint, fields in PEER_FIELDS.items():
        for field in fields:
            yield endpoint, ("zone", "peers", 0, field)
        for field in UPSTREAM_FIELDS[endpoint]:
            yield endpoint, ("zone", field)
        if endpoint.startswith("http/"):
            for code in range(1, 6):
                yield endpoint, ("zone", "peers", 0, "responses", f"{code}xx")


def replace_field(payload, path, value):
    result = copy.deepcopy(payload)
    parent = result
    for key in path[:-1]:
        parent = parent[key]
    parent[path[-1]] = value
    return result


def invalid_tables(endpoint):
    # Cover each union alternative, including empty containers and null.
    wrong_maps = [5, "value", None, True, [], [1]]
    yield from wrong_maps
    for value in wrong_maps:
        yield {"zone": value}
    if endpoint.endswith("upstreams"):
        for value in [5, "value", None, True, {}]:
            yield {"zone": {"peers": value}}
        for value in wrong_maps:
            yield {"zone": {"peers": [value]}}
        for value in [5, 2**63, -1, None, True, [], {}]:
            yield {"zone": {"peers": [{"server": value}]}}
        yield {"zone": {"peers": [{}]}}
        if endpoint.startswith("http/"):
            for value in wrong_maps:
                yield {"zone": {"peers": [{"server": "127.0.0.1:80", "responses": value}]}}
    else:
        field = "sessions" if endpoint.startswith("stream/") else "responses"
        for value in wrong_maps:
            yield {"zone": {field: value}}


@pytest.fixture
def plus_endpoint(tmp_path, request):
    endpoint, api_version = request.param if isinstance(request.param, tuple) else (request.param, 5)
    state = {"payload": valid_response(endpoint), "requests": 0}
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def do_GET(self):
            with lock:
                if self.path == "/status/":
                    payload = list(range(1, api_version + 1))
                elif self.path == f"/status/{api_version}/{endpoint}":
                    payload = state["payload"]
                    state["requests"] += 1
                else:
                    payload = valid_response(self.path.removeprefix(f"/status/{api_version}/"))
                body = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    exporter_port = find_available_port()
    config = tmp_path / "nginx.yaml"
    config.write_text(yaml.safe_dump({
        "service": {"flush": 0.1, "grace": 1, "http_server": True,
                    "http_port": "${FLUENT_BIT_HTTP_MONITORING_PORT}"},
        "pipeline": {
            "inputs": [{"name": "nginx_metrics", "host": "127.0.0.1",
                        "port": server.server_port, "status_url": "/status",
                        "nginx_plus": True, "scrape_interval": "1s", "tag": "nginx"}],
            "outputs": [{"name": "prometheus_exporter", "match": "*",
                         "host": "127.0.0.1", "port": exporter_port}],
        },
    }))
    service = FluentBitTestService(str(config))

    def wait_status(value, minimum_requests, check=None):
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            assert service.flb.process.poll() is None, "Fluent Bit crashed during scrape"
            with lock:
                count = state["requests"]
            try:
                text = requests.get(f"http://127.0.0.1:{exporter_port}/metrics", timeout=1).text
                if count >= minimum_requests and re.search(
                    rf"^nginxplus_up {value}(?:\.0)?(?: |$)", text, re.MULTILINE
                ) and (check is None or check(text)):
                    return text
            except requests.RequestException:
                pass
            time.sleep(0.1)
        pytest.fail(f"scrape status did not become {value}; endpoint={endpoint}")

    def exchange(payload, up=1, check=None):
        with lock:
            state["payload"] = payload
            minimum = state["requests"] + 1
        return wait_status(up, minimum, check)

    try:
        service.start()
        wait_status(1, 1)
        yield endpoint, exchange
    finally:
        try:
            service.stop()
        finally:
            server.shutdown()
            server.server_close()
            thread.join()


@pytest.mark.parametrize("plus_endpoint", TABLES, indirect=True)
def test_plus_rejects_malformed_tables_and_recovers(plus_endpoint):
    endpoint, exchange = plus_endpoint
    for payload in invalid_tables(endpoint):
        exchange(payload, up=0)
        metrics = exchange(valid_response(endpoint))
        assert "zone" in metrics
        if endpoint.endswith("upstreams"):
            assert re.search(r'server="127.0.0.1:80"[^\n]*\} 7(?: |$)', metrics, re.MULTILINE)


@pytest.mark.parametrize("plus_endpoint, path", list(numeric_cases()), indirect=["plus_endpoint"])
def test_plus_rejects_malformed_scalars_and_recovers(plus_endpoint, path):
    endpoint, exchange = plus_endpoint
    healthy = valid_response(endpoint)
    for value in WRONG_NUMBERS:
        exchange(replace_field(healthy, path, value), up=0)
        exchange(healthy)


def state_metric(endpoint, text, expected):
    prefix = "nginxplus_stream" if endpoint.startswith("stream/") else "nginxplus"
    return re.search(rf"^{prefix}_upstream_server_state\{{[^\n]*\}} {expected}(?: |$)",
                     text, re.MULTILINE)


@pytest.mark.parametrize("plus_endpoint", list(PEER_FIELDS), indirect=True)
def test_plus_upstream_state_strings(plus_endpoint):
    endpoint, exchange = plus_endpoint
    healthy = valid_response(endpoint)
    path = ("zone", "peers", 0, "state")
    for value in [1, 1.5, None, True, [], {}, "", "UP", "upstream", "unknown"]:
        exchange(replace_field(healthy, path, value), up=0)
        exchange(healthy, check=lambda text: state_metric(endpoint, text, 1))
    for state, expected in STATES.items():
        exchange(replace_field(healthy, path, state),
                 check=lambda text, expected=expected: state_metric(endpoint, text, expected))


@pytest.mark.parametrize("plus_endpoint", list(FLAT_FIELDS) + TABLES, indirect=True)
def test_plus_unsigned_scalar_boundaries(plus_endpoint):
    endpoint, exchange = plus_endpoint
    healthy = valid_response(endpoint)
    # Test a consumed counter on every endpoint, including integers above INT64_MAX.
    if endpoint in FLAT_FIELDS:
        path = (FLAT_FIELDS[endpoint][0],)
    elif endpoint in ZONE_FIELDS:
        path = ("zone", ZONE_FIELDS[endpoint][0])
    else:
        path = ("zone", "peers", 0, "received")
    for value in [0, 2**63, 2**64 - 1]:
        exchange(replace_field(healthy, path, None), up=0)
        metrics = exchange(replace_field(healthy, path, value))
        # A signed union read would turn the two large values negative.
        values = [float(value) for value in re.findall(
            r"^nginxplus_\w+(?:\{[^\n]*\})? ([^\s]+)", metrics, re.MULTILINE
        )]
        assert float(value) in values


@pytest.mark.parametrize("plus_endpoint", ["http/server_zones"], indirect=True)
def test_plus_metric_families_and_response_labels(plus_endpoint):
    """Keep Plus metric families distinct and response labels associated with their values."""
    endpoint, exchange = plus_endpoint
    metrics = exchange(valid_response(endpoint))
    for name, label in [
        ("nginxplus_server_zone_discarded", "server_zone"),
        ("nginxplus_location_zone_discarded", "location_zone"),
        ("nginxplus_server_zone_sent", "server_zone"),
        ("nginxplus_stream_server_zone_sent", "server_zone"),
    ]:
        assert re.search(rf'^{name}\{{{label}="zone"\}} 7(?: |$)', metrics, re.MULTILINE)
        assert len(re.findall(rf"^# HELP {name} ", metrics, re.MULTILINE)) == 1
        assert len(re.findall(rf"^# TYPE {name} counter$", metrics, re.MULTILINE)) == 1
    assert re.search(
        r'^nginxplus_upstream_server_responses\{upstream="zone",'
        r'server="127.0.0.1:80",code="2xx"\} 3(?: |$)', metrics, re.MULTILINE
    )


@pytest.mark.parametrize("plus_endpoint", [
    (endpoint, version) for endpoint in PEER_FIELDS for version in [4, 5, 7, 10]
], indirect=True)
def test_plus_public_upstream_schema_preserves_gauges(plus_endpoint):
    """Accept documented max_conns and preserve timings regardless of JSON key order."""
    endpoint, exchange = plus_endpoint
    payload = valid_response(endpoint)
    peer = payload["zone"]["peers"][0]
    del peer["limit"]
    peer["max_conns"] = 20
    peer["response_time"] = 36
    timings = {"response_time": 36}
    if endpoint.startswith("http/"):
        peer["header_time"] = 19
        peer["responses"]["codes"] = {"200": 3}
        peer["response_time_hist"] = {"count": 1, "sum": 36, "buckets": {"50": 1}}
        timings["header_time"] = 19
    else:
        peer["connect_time"] = 13
        peer["first_byte_time"] = 17
        timings.update(connect_time=13, first_byte_time=17)
    peer["ssl"] = {"handshakes": 1, "verify_failures": {"other": 0}}
    prefix = "nginxplus_stream" if endpoint.startswith("stream/") else "nginxplus"
    expected = {"limit": 20, **timings}

    def gauges_match(metrics):
        return all(re.search(
            rf'^{prefix}_upstream_server_{field}\{{upstream="zone",'
            rf'server="127.0.0.1:80"\}} {value}(?: |$)', metrics, re.MULTILINE
        ) for field, value in expected.items())

    for reverse in [False, True]:
        payload["zone"]["peers"] = [dict(reversed(list(peer.items()))) if reverse else peer]
        exchange(payload, check=gauges_match)
    exchange(replace_field(payload, ("zone", "peers", 0, "max_conns"), "20"), up=0)
    exchange(payload, check=gauges_match)


@pytest.mark.parametrize("plus_endpoint", list(FLAT_FIELDS) + TABLES, indirect=True)
def test_plus_ignores_unknown_key_prefixes(plus_endpoint):
    """Future API fields must not be parsed as prefixes of existing scalar fields."""
    endpoint, exchange = plus_endpoint
    payload = valid_response(endpoint)
    if endpoint in PEER_FIELDS:
        target = payload["zone"]["peers"][0]
    elif endpoint in ZONE_FIELDS:
        target = payload["zone"]
    else:
        target = payload
    target.update({"": {}, "re": {"future": True}, "s": [], "a": False})
    field = ("active" if endpoint in PEER_FIELDS else ZONE_FIELDS[endpoint][0]
             if endpoint in ZONE_FIELDS else FLAT_FIELDS[endpoint][0])
    target[field] = 19
    exchange(payload, check=lambda text: re.search(
        r"^nginxplus_\w+(?:\{[^\n]*\})? 19(?: |$)", text, re.MULTILINE
    ))
